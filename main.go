package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/widget"
	"github.com/fynelabs/fyneselfupdate"
	"github.com/fynelabs/selfupdate"
	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/layers"
	_ "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

var iface = flag.String("i", "Ethernet", "Interface to get packets from")
var fname = flag.String("r", "", "Filename to read from, overrides -i")
var snaplen = flag.Int("s", 1600, "SnapLen for pcap packet capture")
var filter = flag.String("f", "tcp and dst port 80", "BPF filter for pcap")
var logAllPackets = flag.Bool("v", false, "Logs every packet in great detail")

func selfUpdate(a fyne.App, w fyne.Window) {
	// Used `selfupdatectl create-keys` followed by `selfupdatectl print-key`
	publicKey := ed25519.PublicKey{22, 248, 212, 224, 181, 248, 110, 37, 118, 222, 34, 20, 180, 89, 45, 177, 141, 34, 132, 45, 157, 189, 223, 198, 43, 182, 78, 64, 152, 110, 75, 216}

	// The public key above match the signature of the below file served by our CDN
	httpSource := selfupdate.NewHTTPSource(nil, "https://rps.s3.fr-par.scw.cloud/fyne-cross/bin/{{.OS}}-{{.Arch}}/RPS{{.Ext}}")

	config := fyneselfupdate.NewConfigWithTimeout(a, w, time.Duration(1)*time.Minute,
		httpSource,
		selfupdate.Schedule{FetchOnStart: true, Interval: time.Hour * time.Duration(12)},
		publicKey)

	_, err := selfupdate.Manage(config)
	if err != nil {
		log.Println("Error while setting up update manager: ", err)
		return
	}

}

func spawnWindow() {
	a := app.New()
	w := a.NewWindow("Hello")
	c := container.NewVBox()

	var bars [10]*widget.ProgressBar
	for i := 0; i <= 9; i += 1 {
		bars[i] = widget.NewProgressBar()
		bars[i].SetValue(float64(i) * 0.1)
		c.Add(bars[i])
	}

	if desk, ok := a.(desktop.App); ok {
		m := fyne.NewMenu("MyApp",
			fyne.NewMenuItem("Show", func() {
				w.Show()
			}),
			fyne.NewMenuItem("Update", func() {
				fyneselfupdate.NewUpgradeConfirmCallbackWithTimeout(w, time.Second*5)
				fyneselfupdate.NewProgressCallback(w)
				fyneselfupdate.NewRestartConfirmCallbackWithTimeout(w, time.Second*5)
			}))
		desk.SetSystemTrayMenu(m)
	}

	w.SetContent(widget.NewLabel("Fyne System Tray"))
	// w.SetCloseIntercept(func() {
	// 	w.Hide()
	// })
	selfUpdate(a, w)
	w.SetContent(c)

	w.ShowAndRun()
}

// totoStreamFactory implements tcpassembly.StreamFactory
type totoStreamFactory struct{}

// totoStream will handle the actual decoding of toto requests.
type totoStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
}

func (h *totoStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	hstream := &totoStream{
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
	}
	go hstream.run() // Important... we must guarantee that data from the reader stream is read.

	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
	return &hstream.r
}

func (h *totoStream) run() {
	log.Println("toto packet")
	buf := bufio.NewReader(&h.r)
	buffer := make([]byte, 256)
	for {
		_, err := buf.Read(buffer)
		if err != nil {

			if err != io.EOF {
				fmt.Println(err)
			}

			break
		}

		fmt.Printf("%s", hex.Dump(buffer))
		if err == io.EOF {
			// We must read until we see an EOF... very important!
			return
		} else if err != nil {
			log.Println("Error reading stream", h.net, h.transport, ":", err)
		} else {

		}
	}
}

func main() {
	defer util.Run()()
	var handle *pcap.Handle
	var err error
	// spawnWindow()

	log.Println("readinge in packets\r")

	if *fname != "" {
		log.Printf("Reading from pcap dump %q", *fname)
		handle, err = pcap.OpenOffline(*fname)
	} else {
		log.Printf("Starting capture on interface %q", *iface)
		handle, err = pcap.OpenLive(*iface, int32(*snaplen), true, pcap.BlockForever)
	}
	if err != nil {
		log.Fatal(err)
	}

	if err := handle.SetBPFFilter(*filter); err != nil {
		log.Fatal(err)
	}

	// Set up assembly
	streamFactory := &totoStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	log.Println("readinge in packets")
	// Read in packets, pass to assembler.
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	fmt.Printf("%v", packetSource)
	packets := packetSource.Packets()
	fmt.Printf("%v", packets)
	ticker := time.Tick(time.Minute)
	for {
		select {
		case packet := <-packets:
			// A nil packet indicates the end of a pcap file.
			if packet == nil {
				return
			}
			if *logAllPackets {
				log.Println(packet)
			}
			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
				log.Println("Unusable packet")
				continue
			}
			tcp := packet.TransportLayer().(*layers.TCP)
			assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)

		case <-ticker:
			// Every minute, flush connections that haven't seen activity in the past 2 minutes.
			assembler.FlushOlderThan(time.Now().Add(time.Minute * -2))
		default:
			log.Println("wtf")
		}
	}
}
