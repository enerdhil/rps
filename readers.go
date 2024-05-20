package main

import (
	"encoding/binary"
	"math"
)

// Read a boolean from a ByteArray, returns the boolean and the size read (always 1)
func readBoolean(data []byte) (value bool, size int) {
	value = data[0] != 0
	size = 1
	return
}

// Read a byte from a ByteArray, returns the byte and the size read (always 1)
func readByte(data []byte) (value byte, size int) {
	value = data[0]
	size = 1
	return
}

// Read a short from a ByteArray, returns an int16 and the size read (always 2)
func readShort(data []byte) (value int16, size int) {
	value = int16(binary.BigEndian.Uint16(data[0:2]))
	size = 2
	return
}

// Read an unsigned short from a ByteArray, returns an uint16 and the size read (always 2)
func readUnsignedShort(data []byte) (value uint16, size int) {
	value = binary.BigEndian.Uint16(data[0:2])
	size = 2
	return
}

// Read an int from a ByteArray, returns an int32 and the size read (always 4)
func readInt(data []byte) (value int32, size int) {
	value = int32(binary.BigEndian.Uint32(data[0:4]))
	size = 4
	return
}

// Read an unsigned int from a ByteArray, returns an uint32 and the size read (always 4)
func readUnsignedInt(data []byte) (value uint32, size int) {
	value = binary.BigEndian.Uint32(data[0:4])
	size = 4
	return
}

// Read an double from a ByteArray, returns a float64 and the size read (always 4)
func readDouble(data []byte) (value float64, size int) {
	value = math.Float64frombits(binary.BigEndian.Uint64(data[0:8]))
	size = 8
	return
}

// Read an string from a ByteArray, returns the string and the size read
func readString(data []byte) (value string, size int) {
	stringLen, _ := readUnsignedShort(data)
	value = string(data[2 : 2+stringLen])
	size = 2 + int(stringLen)
	return
}

// Read a short from a ByteArray, returns an int16 and the size read (always 2)
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

func readVarUint(data []byte) (value uint32, size int) {
	var tmpValue int32
	tmpValue, size = readVarInt(data)
	value = uint32(tmpValue)
	if tmpValue < 0 {
		value = uint32(tmpValue) + math.MaxUint16
	}
	return
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
