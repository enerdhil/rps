// Copyright 2014, 2018 GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package main

import (
	"encoding/binary"
	"errors"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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
//  Dofus Header
//  0   1   2   3   4   5   6   7   8   9   10  11  12  13  14  15
//  +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//  |                           ProtocolId                  |LenSize|
//  +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//  |             MsgLen            |    MsgLen (if LenSize == 2)   |
//  +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//  |    MsgLen (if LenSize == 3)   |              n/a              |
//  +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//
//  As we see in the schema, the len of the message is variable in
//  size. We first need to get LenSize to know on how many bytes we
//  need to read MsgLen.
//
//  If LenSize is 3, the pseudocode to get the value is the following
//  (uint)(((msgLen1 & 255) << 16) + ((msgLen2 & 255) << 8) + (msgLen3 & 255))

var LayerTypeDofusMsg = gopacket.RegisterLayerType(1894, gopacket.LayerTypeMetadata{Name: "Dofus", Decoder: gopacket.DecodeFunc(decodeDofusMsg)})

// DofusMsg contains data from a single Dofus message.
type DofusMsg struct {
	layers.BaseLayer

	// Header fields
	ProtocolId uint16
	LenSize    uint8
	MsgLen     uint32

	buffer []byte
}

// LayerType returns gopacket.LayerTypeDofusMsg.
func (d *DofusMsg) LayerType() gopacket.LayerType { return LayerTypeDofusMsg }

// decodeDNS decodes the byte slice into a DNS type. It also
// setups the application Layer in PacketBuilder.
func decodeDofusMsg(data []byte, p gopacket.PacketBuilder) error {
	d := &DofusMsg{}
	log.Println("Try decoding dofusmsg")
	err := d.DecodeFromBytes(data, p)
	if err != nil {
		log.Println("Error decoding dofusmsg")
		return err
	}
	p.AddLayer(d)
	p.SetApplicationLayer(d)
	return nil
}

// DecodeFromBytes decodes the slice into the DNS struct.
func (d *DofusMsg) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	d.buffer = d.buffer[:0]

	if len(data) < 2 {
		df.SetTruncated()
		return errDofusMsgTooShort
	}

	// since there are no further layers, the baselayer's content is
	// pointing to this layer
	d.BaseLayer = layers.BaseLayer{Contents: data[:]}
	d.ProtocolId = binary.BigEndian.Uint16(data[:2]) >> 2
	d.LenSize = data[1] & 0x3
	switch d.LenSize {
	case 0:
		d.MsgLen = 0
	case 1:
		d.MsgLen = uint32(data[2])
	case 2:
		d.MsgLen = uint32(binary.BigEndian.Uint16(data[2:3]))
	case 3:
		d.MsgLen = uint32((data[2] << 16) + (data[3] << 8) + (data[4]))
	}
	log.Println(d)

	return nil
}

// CanDecode implements gopacket.DecodingLayer.
func (d *DofusMsg) CanDecode() gopacket.LayerClass {
	return LayerTypeDofusMsg
}

// NextLayerType implements gopacket.DecodingLayer.
func (d *DofusMsg) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// Payload returns nil.
func (d *DofusMsg) Payload() []byte {
	return nil
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// func (d *DofusMsg) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
// 		Placeholder, dont think we need it
// }

var (
	errDofusMsgTooShort = errors.New("Dofus message is too short for header")
)
