package main

import (
	"encoding/binary"
	"math"
	"reflect"
)

type dofusField struct {
	fieldType reflect.Type
	reader    func(data []byte) (value bool, size int)
}

func readBoolean(data []byte) (value bool, size int) {
	value = data[0] != 0
	size = 1
	return
}

func readByte(data []byte) (value byte, size int) {
	value = data[0]
	size = 1
	return
}

func readShort(data []byte) (value int16, size int) {
	value = int16(binary.BigEndian.Uint16(data[0:2]))
	size = 2
	return
}

func readUnsignedShort(data []byte) (value uint16, size int) {
	value = binary.BigEndian.Uint16(data[0:2])
	size = 2
	return
}

func readInt(data []byte) (value int32, size int) {
	value = int32(binary.BigEndian.Uint32(data[0:4]))
	size = 4
	return
}

func readUnsignedInt(data []byte) (value uint32, size int) {
	value = binary.BigEndian.Uint32(data[0:4])
	size = 4
	return
}

func readDouble(data []byte) (value float64, size int) {
	value = math.Float64frombits(binary.BigEndian.Uint64(data[0:8]))
	size = 8
	return
}

func readString(data []byte) (value string, size int) {
	stringLen, _ := readUnsignedShort(data)
	value = string(data[2 : 2+stringLen])
	size = 2 + int(stringLen)
	return
}

func readVarShort(data []byte) (value int16, size int) {
	for i := 0; i < 16; i += 7 {
		b, byteSize := readByte(data[size:])
		value += int16(b&0b01111111) << i
		size += byteSize
		if b&0b10000000 == 0 {
			return
		}
	}
	return 0, 0 // Error handling for too much data
}

func readVarInt(data []byte) (value int32, size int) {
	var tmpValue int64
	for offset := 0; offset < 32; {
		current, byteSize := readByte(data[size:])

		hasNext := int(current&0b10000000) >> 7
		tmpValue += int64(current&0b01111111) << offset
		offset += 7
		size += byteSize
		if hasNext == 0 {
			if tmpValue > 0 && tmpValue > math.MaxInt32 {
				tmpValue -= int64(math.MaxUint32)
			}
			value = int32(tmpValue)
			return
		}
	}
	return 0, 0 // Error handling for too much data
}

func readVarLong(data []byte) (value int64, size int) {
	for offset := 0; offset < 64; {
		current, byteSize := readByte(data[size:])
		hasNext := int(current&0b10000000) >> 7
		value += int64(current&0b01111111) << offset
		offset += 7
		size += byteSize
		if hasNext == 0 {
			return
		}
	}
	return 0, 0 // Error handling for too much data
}
