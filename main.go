package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"reflect"
	"strings"

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

func readVector(binaryMsg []byte, field reflect.Value) (sizeRead int) {

	vectorSize, sizeRead := readUnsignedShort(binaryMsg)

	fmt.Printf("Vector: %v\n", field.Type().String())

	// Ensure field is a slice
	if field.Kind() != reflect.Slice {
		log.Fatalf("ReadVector: Field is not a slice")
	}

	// Create a new slice to hold the values
	sliceType := field.Type().Elem()
	newSlice := reflect.MakeSlice(field.Type(), int(vectorSize), int(vectorSize))

	for i := 0; i < int(vectorSize); i++ {
		switch sliceType {
		case reflect.TypeOf(uint8(0)):
			value, size := readByte(binaryMsg[sizeRead:])
			sizeRead += size
			newSlice.Index(i).SetUint(uint64(value))
			fmt.Printf("Added %v value: %v\n", reflect.TypeOf(value), value)
		case reflect.TypeOf(string("")):
			value, size := readString(binaryMsg[sizeRead:])
			sizeRead += size
			newSlice.Index(i).SetString(value)
			fmt.Printf("Added %v value: %v\n", reflect.TypeOf(value), value)
		case reflect.TypeOf(uint32(0)):
			value, size := readUnsignedInt(binaryMsg[sizeRead:])
			sizeRead += size
			newSlice.Index(i).SetUint(uint64(value))
			fmt.Printf("Added %v value: %v\n", reflect.TypeOf(value), value)
		case reflect.TypeOf(int32(0)):
			value, size := readInt(binaryMsg[sizeRead:])
			sizeRead += size
			newSlice.Index(i).SetInt(int64(value))
			fmt.Printf("Added %v value: %v\n", reflect.TypeOf(value), value)
		case reflect.TypeOf(float64(0.0)):
			value, size := readDouble(binaryMsg[sizeRead:])
			sizeRead += size
			newSlice.Index(i).SetFloat(value)
			fmt.Printf("Added %v value: %v\n", reflect.TypeOf(value), value)
		default:
			log.Fatalf("ReadVector: Unimplemented type: %s, at index\n", field.Type().String())
		}
	}

	// Set the new slice to the field
	field.Set(newSlice)

	return sizeRead
}

func readField(binaryMsg []byte, field reflect.Value) (sizeRead int) {
	switch field.Kind() {
	case reflect.Uint8:
		value, size := readByte(binaryMsg)
		sizeRead = size
		field.SetUint(uint64(value))
		fmt.Printf("Added %v value: %v\n", reflect.TypeOf(value), value)
	case reflect.String:
		value, size := readString(binaryMsg)
		sizeRead = size
		field.SetString(value)
		fmt.Printf("Added %v value: %v\n", reflect.TypeOf(value), value)
	case reflect.Uint32:
		value, size := readUnsignedInt(binaryMsg)
		sizeRead = size
		field.SetUint(uint64(value))
		fmt.Printf("Added %v value: %v\n", reflect.TypeOf(value), value)
	case reflect.Int32:
		value, size := readInt(binaryMsg)
		sizeRead = size
		field.SetInt(int64(value))
		fmt.Printf("Added %v value: %v\n", reflect.TypeOf(value), value)
	case reflect.Float64:
		value, size := readDouble(binaryMsg)
		sizeRead = size
		field.SetFloat(value)
		fmt.Printf("Added %v value: %v\n", reflect.TypeOf(value), value)
	default:
		log.Fatalf("Unimplemented type: %s, at index\n", field.Kind())
	}
	return
}

func createStruct(packet dofusMsg) {
	schemaBytes := gjson.GetBytes(messagesJson, fmt.Sprintf("%v", packet.ProtocolId))

	// Unmarshal the JSON schema into a Schema struct
	var schema Schema
	if err := json.Unmarshal([]byte(schemaBytes.Raw), &schema); err != nil {
		log.Fatal(err)
	}

	// Dynamically create Message struct using reflection
	var fields []reflect.StructField
	//var fieldIndexMethodMap map[int]string
	for _, field := range schema.Fields {
		fields = append(fields, reflect.StructField{
			Name: strings.Title(field.Name),
			Type: getFieldType(field),
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
		if field.Kind() == reflect.Slice {
			fmt.Printf("%v\n", field.Type())
			offset += readVector(binaryPacket[offset:], field)
		} else {
			offset += readField(binaryPacket[offset:], field)
		}

	}

	// Use the decoded data
	fmt.Printf("Decoded %v (packetsize:%d, read:%d)\n", idNameMap[int(packet.ProtocolId)], len(binaryPacket), offset)
	for i := 0; i < instance.NumField(); i++ {
		field := instance.Type().Field(i)
		value := instance.Field(i).Interface()
		fmt.Printf("%s: %v\n", field.Name, value)
	}
	fmt.Println("===============================")
	//fmt.Printf("Field : %v\n", instance.FieldByName("Content"))

}

func parseArchi() {
	for packet := range havenBagInventoryPackets {
		fmt.Printf("%v\n", packet.ProtocolId)
		createStruct(packet)
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
	case "ChatServerMessage":
		fallthrough
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

	for true {

	}
	// fmpackets := make(chan int)

	// go combat(combatpackets)
	// go fm(fmpackets)

}
