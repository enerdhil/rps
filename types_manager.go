package main

import (
	"log"
	"reflect"
)

func getFieldType(field MessageField) (fieldType reflect.Type) {
	switch field.Type {
	case "Boolean":
		fieldType = reflect.TypeOf(true)
	case "String":
		fieldType = reflect.TypeOf("")
	case "Number":
		switch field.ReadFunc {
		case "readDouble":
			fieldType = reflect.TypeOf(float64(0))
		case "readVarLong":
			fieldType = reflect.TypeOf(uint64(0))
		default:
			log.Fatalf("Unsupported readFunc : %s for type %s field %s", field.ReadFunc, field.Type, field.Name)
		}
	case "int":
		fallthrough
	case "uint":
		fieldType = reflect.TypeOf(uint32(0))
		switch field.ReadFunc {
		case "readByte":
			fieldType = reflect.TypeOf(byte('a'))
		case "readShort":
			fieldType = reflect.TypeOf(uint16(0))
		case "readVarShort":
			fieldType = reflect.TypeOf(uint16(0))
		case "readUnsignedInt":
			fieldType = reflect.TypeOf(uint32(0))
		case "readInt":
			fallthrough
		case "readVarInt":
			fieldType = reflect.TypeOf(int32(0))
		default:
			log.Fatalf("Unsupported readFunc : %s for type %s field %s", field.ReadFunc, field.Type, field.Name)
		}
	default:
		log.Fatalf("Unsupported type: %s for field: %s", field.Type, field.Name)
	}

	if field.IsVector {
		fieldType = reflect.SliceOf(fieldType)
	}
	return
}
