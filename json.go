package main

import (
	"fmt"

	"github.com/tidwall/gjson"
)

func parse_json() error {

	value := gjson.Get(jsonString, "messages.#(protocolID=8285)@this")

	// result, err := gabs.ParseJSONFile(jsonfile)
	// if err != nil {
	// 	return result, err
	// }

	fmt.Printf("%v\n", value)

	// for k, v := range result.Search("messages", "protocolID").String() {
	// 	fmt.Printf("%v : %v\n", k, v)
	// 	// fmt.Printf("Name: %s, Namespace: %s, ProtocolID: %d\n", message.Name, message.Namespace, message.ProtocolID)
	// 	// Access other fields as needed
	// }
	return nil
}
