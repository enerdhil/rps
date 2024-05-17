package main

import (
	"encoding/json"
	"fmt"
	"log"
	"reflect"
	"strings"

	"github.com/tidwall/gjson"
)

// Define structs representing fields and ChatServerMessage
type MessageField struct {
	IsVector         bool   `json:"isVector"`
	Name             string `json:"name"`
	PrefixedByTypeID bool   `json:"prefixedByTypeID"`
	Type             string `json:"type"`
	ReadFunc         string `json:"readFunc"`
	ConstantLength   int    `json:"constantLength"`
}

type MessageSchema struct {
	Fields []MessageField `json:"fields"`
	Name   string         `json:"name"`
}

var fieldTypesMap map[string]reflect.Type

func createFieldType(field MessageField) (fieldType reflect.Type) {
	schemaBytes := gjson.GetBytes(typesJson, fmt.Sprintf("%v", nameIdMap[field.Type]))

	var schema MessageSchema
	// Unmarshal the JSON schema into a Schema struct
	if err := json.Unmarshal([]byte(schemaBytes.Raw), &schema); err != nil {
		log.Fatal(err)
	}

	if fieldTypesMap[schema.Name] != nil {
		return fieldTypesMap[schema.Name]
	}

	// Dynamically create Message struct using reflection
	var fields []reflect.StructField
	//var fieldIndexMethodMap map[int]string
	for _, field := range schema.Fields {
		fields = append(fields, reflect.StructField{
			Name: strings.Title(field.Name),
			Type: getFieldType(field),
			Tag:  reflect.StructTag(fmt.Sprintf("type:\"%v\" prefixed:\"%v\"", field.Type, field.PrefixedByTypeID)),
		})
	}

	messageType := reflect.StructOf(fields)
	fieldTypesMap[schema.Name] = messageType

	return messageType
}

func getFieldType(field MessageField) (fieldType reflect.Type) {
	switch field.Type {
	case "Boolean":
		fieldType = reflect.TypeOf(true)
	case "String":
		fieldType = reflect.TypeOf("")
	case "Number":
		switch field.ReadFunc {
		case "readDouble":
			fallthrough
		case "readFloat":
			fieldType = reflect.TypeOf(float64(0))
		case "readVarLong":
			fieldType = reflect.TypeOf(uint64(0))
		default:
			log.Fatalf("Unsupported readFunc : %s for type %s field %s", field.ReadFunc, field.Type, field.Name)
		}
	case "int":
		fieldType = reflect.TypeOf(uint32(0))
		switch field.ReadFunc {
		case "readByte":
			fieldType = reflect.TypeOf(byte('a'))
		case "readShort":
			fieldType = reflect.TypeOf(int16(0))
		case "readVarShort":
			fieldType = reflect.TypeOf(int16(0))
		case "readInt":
			fallthrough
		case "readVarInt":
			fieldType = reflect.TypeOf(int32(0))
		default:
			log.Fatalf("Unsupported readFunc : %s for type %s field %s", field.ReadFunc, field.Type, field.Name)
		}

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
			fallthrough
		case "readInt":
			fallthrough
		case "readVarInt":
			fieldType = reflect.TypeOf(uint32(0))
		default:
			log.Fatalf("Unsupported readFunc : %s for type %s field %s", field.ReadFunc, field.Type, field.Name)
		}
	default:
		fieldType = createFieldType(field)
	}

	if field.IsVector {
		fieldType = reflect.SliceOf(fieldType)
	}
	return
}
