package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/reassembly"
)

// Dofus Protocol
//
// Standard port is TCP/5555
//
// +---------------------+
// |        Header       |
// +---------------------+
// |       Message       |
// +---------------------+
//
//	Dofus Header
//	0   1   2   3   4   5   6   7   8   9   10  11  12  13  14  15
//	+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//	|                           ProtocolId                  |LenSize|
//	+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//	|             MsgLen            |    MsgLen (if LenSize == 2)   |
//	+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//	|    MsgLen (if LenSize == 3)   |              n/a              |
//	+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//
//	As we see in the schema, the len of the message is variable in
//	size. We first need to get LenSize to know on how many bytes we
//	need to read MsgLen.
//
//	If LenSize is 3, the pseudocode to get the value is the following
//	(uint)(((msgLen1 & 255) << 16) + ((msgLen2 & 255) << 8) + (msgLen3 & 255))
type dofusMsg struct {
	// Header fields
	ProtocolId uint16
	LenSize    uint8
	MsgLen     uint32

	body []byte
}

func (dM *dofusMsg) decode(b *bufio.Reader) error {
	var err error

	// Transform stream to byte slice
	data, err := b.Peek(2)
	if err != nil {
		return err
	}

	// since there are no further layers, the baselayer's content is
	// pointing to this layer
	dM.ProtocolId = binary.BigEndian.Uint16(data[:2]) >> 2
	dM.LenSize = data[1] & 0x3
	switch dM.LenSize {
	case 0:
		dM.MsgLen = 0
	case 1:
		data, err = b.Peek(3)
		if err != nil {
			return err
		}
		dM.MsgLen = uint32(data[2])
	case 2:
		data, err = b.Peek(4)
		if err != nil {
			return err
		}
		dM.MsgLen = uint32(binary.BigEndian.Uint16(data[2:4]))
	case 3:
		data, err = b.Peek(5)
		if err != nil {
			return err
		}
		dM.MsgLen = uint32((data[2] << 16) + (data[3] << 8) + (data[4]))
	}

	if *logAllPackets {
		log.Println("DofusMsg : ")
		log.Printf("ProtocolId: %v\n", dM.ProtocolId)
		log.Printf("ProtocolName: %v\n", idNameMap[dM.ProtocolId])
		log.Printf("LenSize : %v\n", dM.LenSize)
		log.Printf("MsgLen : %v\n", dM.MsgLen)
	}
	b.Discard(int(2 + dM.LenSize))
	dM.body, err = io.ReadAll(io.LimitReader(b, int64(dM.MsgLen)))

	if err != nil {
		return err
	}
	return err
}

type dofusReader struct {
	ident    string
	isClient bool
	bytes    chan []byte
	data     []byte
	parent   *tcpStream
}

func (hR *dofusReader) Read(bytes []byte) (int, error) {
	ok := true
	for len(hR.data) == 0 && ok {
		hR.data, ok = <-hR.bytes
	}
	if !ok || len(hR.data) == 0 {
		return 0, io.EOF
	}
	l := copy(bytes, hR.data)
	hR.data = hR.data[l:]
	return l, nil
}

func (hR *dofusReader) Run(wg *sync.WaitGroup) {
	defer wg.Done()
	b := bufio.NewReader(hR)
	for {
		msg := new(dofusMsg)
		err := msg.decode(b)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		redirectMessage(*msg)
		if *logAllPackets {
			dumpByteSlice(msg.body)
		}
	}
}

type Context struct {
	CaptureInfo gopacket.CaptureInfo
}

func (ac *Context) GetCaptureInfo() gopacket.CaptureInfo {
	return ac.CaptureInfo
}

// Implements a reassembly.Stream
type tcpStream struct {
	net, transport gopacket.Flow
	tcpstate       *reassembly.TCPSimpleFSM
	optchecker     reassembly.TCPOptionCheck
	reversed       bool
	client         dofusReader
	server         dofusReader
	ident          string
}

func (tS *tcpStream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, nextSeq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	if !tS.tcpstate.CheckState(tcp, dir) {
		return false
	}
	if err := tS.optchecker.Accept(tcp, ci, dir, nextSeq, start); err != nil {
		return false
	}
	return true
}

func (tS *tcpStream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	dir, _, _, _ := sg.Info()
	length, _ := sg.Lengths()

	data := sg.Fetch(length)

	if length > 0 {
		if dir == reassembly.TCPDirClientToServer && !tS.reversed {
			tS.client.bytes <- data
		} else {
			tS.server.bytes <- data
		}
	}
}

func (tS *tcpStream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	close(tS.client.bytes)
	close(tS.server.bytes)
	return false
}

// Implements Interface reassembly.StreamFactory
type tcpStreamFactory struct {
	wg sync.WaitGroup
}

func (tSF *tcpStreamFactory) New(netFlow gopacket.Flow, tcpFlow gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {
	fsmOptions := reassembly.TCPSimpleFSMOptions{
		SupportMissingEstablishment: false,
	}

	stream := &tcpStream{
		net:        netFlow,
		transport:  tcpFlow,
		tcpstate:   reassembly.NewTCPSimpleFSM(fsmOptions),
		optchecker: reassembly.NewTCPOptionCheck(),
		reversed:   tcp.SrcPort == 5555,
		ident:      fmt.Sprintf("%s - %s", netFlow, tcpFlow),
	}

	if tcp.SrcPort == 5555 || tcp.DstPort == 5555 {
		stream.client = dofusReader{
			ident:    fmt.Sprintf("%s - %s", netFlow, tcpFlow),
			bytes:    make(chan []byte),
			isClient: true,
			parent:   stream,
		}
		stream.server = dofusReader{
			ident:    fmt.Sprintf("%s - %s", netFlow, tcpFlow),
			bytes:    make(chan []byte),
			isClient: false,
			parent:   stream,
		}
		tSF.wg.Add(2)
		go stream.client.Run(&tSF.wg)
		go stream.server.Run(&tSF.wg)
	}

	return stream
}

func (tSF *tcpStreamFactory) WaitGoRoutines() {
	tSF.wg.Wait()
}

func handlePackets() {
	var err error
	log.Println("start")
	defer log.Println("end")
	flag.Parse()

	var handle *pcap.Handle

	if *pcapfile != "" {
		handle, err = pcap.OpenOffline(*pcapfile)
		if err != nil {
			log.Fatalf("could not open filename - %v - %s", *pcapfile, err)
		}
	} else {
		if *iface == "" {
			log.Fatal("Missing interface name")
		}
		log.Printf("Starting capture on interface %q", *iface)
		handle, err = pcap.OpenLive(*iface, defaultSnapLen, true, pcap.BlockForever)
		if err != nil {
			panic(err)
		}
	}

	defer handle.Close()

	if *filter != "" {
		if err = handle.SetBPFFilter(*filter); err != nil {
			log.Fatalf("could not apply filter %v to capture - %s", *filter, err)
		}
	}

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	source.Lazy = false
	source.NoCopy = true
	source.DecodeStreamsAsDatagrams = false // Same as default, but i put it here for potential tests

	// Create StreamFactory
	streamFactory := &tcpStreamFactory{}
	// Create StreamPool
	streamPool := reassembly.NewStreamPool(streamFactory)
	// Create Assembler
	reassembler := reassembly.NewAssembler(streamPool)

	const closeTimeout time.Duration = time.Hour * 1
	const timeout time.Duration = time.Minute * 1

	count := 0

	for packet := range source.Packets() {

		count++
		//Parse Packet
		if packet == nil {
			return
		}
		if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
			continue
		}

		tcp := packet.Layer(layers.LayerTypeTCP)

		if tcp != nil {
			tcp := tcp.(*layers.TCP)
			context := Context{
				CaptureInfo: packet.Metadata().CaptureInfo,
			}
			if tcp.SrcPort == 5555 || tcp.DstPort == 5555 {
				reassembler.AssembleWithContext(packet.NetworkLayer().NetworkFlow(), tcp, &context)
			}
		}

		if count%1000 == 0 {
			timestamp := packet.Metadata().CaptureInfo.Timestamp
			reassembler.FlushWithOptions(reassembly.FlushOptions{T: timestamp.Add(-timeout), TC: timestamp.Add(-closeTimeout)})
		}
	}

	log.Println("iterated all packets")

	reassembler.FlushAll()
	log.Println("flushed all connections")
	streamFactory.WaitGoRoutines()
	log.Println("all go routines finished")

}
