package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/buger/jsonparser"
	"github.com/tidwall/gjson"
)

var iface = flag.String("i", "Ethernet", "Interface to get packets from")
var pcapfile = flag.String("r", "", "Pcap file to read from")
var filter = flag.String("f", "tcp port 5555", "BPF filter for pcap")
var listInterfaces = flag.Bool("l", false, "List all interfaces on the system")
var logAllPackets = flag.Bool("v", false, "Logs every packet in great detail")
var defaultSnapLen int32 = 262144
var messagesJson, typesJson []byte

var chatPackets chan dofusMsg
var havenBagInventoryPackets chan dofusMsg

// Define structs representing fields and ChatServerMessage
type MessageField struct {
	IsVector         bool   `json:"isVector"`
	Name             string `json:"name"`
	PrefixedByTypeID bool   `json:"prefixedByTypeID"`
	Type             string `json:"type"`
	ReadFunc         string `json:"readFunc"`
	ConstantLength   int    `json:"constantLength"`
}

type Schema struct {
	Fields []MessageField `json:"fields"`
	Name   string         `json:"name"`
}

// func readField(bina)

func createStruct(packet dofusMsg) {
	schemaBytes := gjson.GetBytes(messagesJson, fmt.Sprintf("%v", packet.ProtocolId))

	// Unmarshal the JSON schema into a Schema struct
	var schema Schema
	if err := json.Unmarshal([]byte(schemaBytes.Raw), &schema); err != nil {
		log.Fatal(err)
	}

	// Dynamically create ChatServerMessage struct using reflection
	var fields []reflect.StructField
	for _, field := range schema.Fields {
		var fieldType reflect.Type
		switch field.Type {
		case "Boolean":
			switch field.IsVector {
			case true:
				fieldType = reflect.TypeOf([]bool{true})
			case false:
				fieldType = reflect.TypeOf(true)
			}
		case "String":
			fieldType = reflect.TypeOf("")
		case "Number":
			switch field.IsVector {
			case true:
				fmt.Printf("Its a vector")
				switch field.ReadFunc {
				case "readDouble":
					fieldType = reflect.TypeOf([]float64{0})
				case "readVarLong":
					fieldType = reflect.TypeOf([]uint64{0})
				default:
					log.Fatalf("Unsupported readFunc : %s for type %s field %s", field.ReadFunc, field.Type, field.Name)
				}
			case false:
				switch field.ReadFunc {
				case "readDouble":
					fieldType = reflect.TypeOf(float64(0))
				case "readVarLong":
					fieldType = reflect.TypeOf(uint64(0))
				default:
					log.Fatalf("Unsupported readFunc : %s for type %s field %s", field.ReadFunc, field.Type, field.Name)
				}
			}
		case "uint":
			switch field.ReadFunc {
			case "readByte":
				fieldType = reflect.TypeOf(byte('a'))
			case "readInt":
				fieldType = reflect.TypeOf(uint32(0))
			default:
				log.Fatalf("Unsupported readFunc : %s for type %s field %s", field.ReadFunc, field.Type, field.Name)
			}
		// Add other types as needed
		default:
			log.Fatalf("Unsupported type: %s for field: %s", field.Type, field.Name)
		}
		fields = append(fields, reflect.StructField{
			Name: strings.Title(field.Name),
			Type: fieldType,
		})
	}

	// Create an instance of ChatServerMessage
	messageType := reflect.StructOf(fields)
	instance := reflect.New(messageType).Elem()

	// Example binary packet
	binaryPacket := packet.body // "Hello" (string) followed by 5 (int)

	// Decode the binary packet according to the dynamic schema
	offset := 0
	for i := 0; i < instance.NumField(); i++ {
		field := instance.Field(i)
		// fmt.Printf("loop %v, offset: %v\n", i, offset)
		switch field.Kind() {
		case reflect.Uint8:
			value, size := readByte(binaryPacket[offset:])
			offset += size
			field.SetUint(uint64(value))
			fmt.Printf("Added %v value: %v\n", reflect.TypeOf(value), value)
		case reflect.String:
			value, size := readString(binaryPacket[offset:])
			offset += size
			field.SetString(value)
			fmt.Printf("Added %v value: %v\n", reflect.TypeOf(value), value)
		case reflect.Uint32:
			value, size := readUnsignedInt(binaryPacket[offset:])
			offset += size
			field.SetUint(uint64(value))
			fmt.Printf("Added %v value: %v\n", reflect.TypeOf(value), value)
		case reflect.Float64:
			value, size := readDouble(binaryPacket[offset:])
			offset += size
			field.SetFloat(value)
			fmt.Printf("Added %v value: %v\n", reflect.TypeOf(value), value)
		case reflect.Slice:
			log.Fatalf("Unimplemented type: %s, at index %v\n", field.Kind(), i)
		default:
			log.Fatalf("Unimplemented type: %s, at index %v\n", field.Kind(), i)
		}
	}

	time.Sleep(12)
	// Use the decoded data
	fmt.Printf("Decoded %v\n", idNameMap[int(packet.ProtocolId)])
	for i := 0; i < instance.NumField(); i++ {
		field := instance.Type().Field(i)
		value := instance.Field(i).Interface()
		fmt.Printf("%s: %v\n", field.Name, value)
	}
	fmt.Println("===============================")
	fmt.Printf("Field : %v\n", instance.FieldByName("Content"))

}

func parseArchi() {
	for packet := range havenBagInventoryPackets {
		jsonparser.ArrayEach(messagesJson, func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
			fmt.Println(jsonparser.GetString(value, "name"))
		}, fmt.Sprintf("%v", packet.ProtocolId), "fields")
	}
}

func beatbox() {
	for packet := range chatPackets {
		fmt.Printf("%v\n", packet.ProtocolId)
		createStruct(packet)
	}
}

func redirectMessage(message dofusMsg) {
	// fmt.Printf("%v\n", idNameMap[int(message.ProtocolId)])
	switch messageName := idNameMap[int(message.ProtocolId)]; messageName {
	// case "ChatServerMessage":
	// 	fallthrough
	case "KnownZaapListMessage":
		chatPackets <- message
	case "StorageInventoryContentMessage":
		havenBagInventoryPackets <- message
	}
}

func main() {
	var err error
	log.Println("start")
	defer log.Println("end")
	flag.Parse()

	bytesJSON, err := os.ReadFile("toto.json")
	if err != nil {
		log.Fatal(err)
	}

	messagesJson, typesJson, err = json_epurate(bytesJSON)
	if err != nil {
		log.Fatal(err)
	}

	if *listInterfaces {
		ListInterfaces()
		return
	}

	chatPackets = make(chan dofusMsg)
	go beatbox()
	havenBagInventoryPackets = make(chan dofusMsg)
	go parseArchi()

	handlePackets()

	// fmpackets := make(chan int)

	// go combat(combatpackets)
	// go fm(fmpackets)

}
