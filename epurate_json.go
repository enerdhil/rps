package main

import (
	"encoding/json"
	"fmt"
	"os"
)

var data map[string][]Object

// Create a ProtocolID = "MessageName" map
var idNameMap map[uint16]string

// Create a "MessageName"= ProtocolID map
var nameIdMap map[string]uint16

type Bounds struct {
	Low string `json:"low"`
	Up  string `json:"up"`
}

type Field struct {
	Boolean_byte_wrapper_position int    `json:"boolean_byte_wrapper_position"`
	Bounds                        Bounds `json:"bounds"`
	Constant_length               int    `json:"constant_length"`
	Default_value                 string `json:"default_value"`
	Is_vector                     bool   `json:"is_vector"`
	Name                          string `json:"name"`
	Namespace                     string `json:"namespace"`
	Null_checked                  bool   `json:"null_checked"`
	Position                      int    `json:"position"`
	Prefixed_by_type_id           bool   `json:"prefixed_by_type_id"`
	Self_serialize_method         string `json:"self_serialize_method"`
	Type                          string `json:"type"`
	Type_namespace                string `json:"type_namespace"`
	Use_boolean_byte_wrapper      bool   `json:"use_boolean_byte_wrapper"`
	Write_false_if_null_method    string `json:"write_false_if_null_method"`
	Write_length_method           string `json:"write_length_method"`
	Write_method                  string `json:"write_method"`
	Write_type_id_method          string `json:"write_type_id_method"`
}

type Object struct {
	Fields            []Field `json:"fields"`
	Name              string  `json:"name"`
	Namespace         string  `json:"namespace"`
	ProtocolID        uint16  `json:"protocolID"`
	Super             string  `json:"super"`
	Super_serialize   bool    `json:"super_serialize"`
	Supernamespace    string  `json:"supernamespace"`
	Use_hash_function bool    `json:"use_hash_function"`
}

func superRecurse(object Object, root string) (fieldSlice []map[string]interface{}) {
	for i := 0; i < len(object.Fields); i++ {
		for _, field := range object.Fields {
			if field.Position != i {
				continue
			}
			fieldMap := make(map[string]interface{})

			fieldMap["name"] = field.Name
			fieldMap["type"] = field.Type
			fieldMap["isVector"] = field.Is_vector
			fieldMap["prefixedByTypeID"] = field.Prefixed_by_type_id

			if field.Write_method != "" {
				fieldMap["readFunc"] = "read" + field.Write_method[5:]
			}

			if field.Constant_length != 0 {
				fieldMap["constantLength"] = field.Constant_length
			}

			if field.Position != -1 {
				fieldSlice = append(fieldSlice, fieldMap)
			}
		}
	}
	if !object.Super_serialize || object.Super == "" {
		return fieldSlice
	}
	for _, value := range data[root] {
		if object.Super == value.Name {
			return append(superRecurse(value, root), fieldSlice...)
		}
	}
	return fieldSlice
}

func json_epurate(jsonBytes []byte) ([]byte, []byte, error) {
	var err error
	if err = json.Unmarshal(jsonBytes, &data); err != nil {
		panic(err)
	}

	nameIdMap = make(map[string]uint16)
	idNameMap = make(map[uint16]string)
	messages := make(map[string]map[string]interface{})
	types := make(map[string]map[string]interface{})

	for root, output := range map[string]map[string]map[string]interface{}{"messages": messages, "types": types} {
		for _, obj := range data[root] {
			var fieldSlice []map[string]interface{}
			// Fill the ProtocolID="Name" map
			idNameMap[obj.ProtocolID] = obj.Name
			// Fill the "Name"=ProtocolID map
			nameIdMap[obj.Name] = obj.ProtocolID

			// Make objects without the unnecessary data
			messageMap := make(map[string]interface{})
			fieldSlice = superRecurse(obj, root)
			messageMap["fields"] = fieldSlice
			messageMap["name"] = obj.Name
			output[fmt.Sprintf("%d", obj.ProtocolID)] = messageMap
		}

		jsonOutput, err := json.MarshalIndent(output, "", "    ")
		if err != nil {
			panic(err)
		}

		file, err := os.Create(fmt.Sprintf("result_%v.json", root))
		if err != nil {
			panic(err)
		}
		defer file.Close()

		_, err = file.Write(jsonOutput)
		if err != nil {
			panic(err)
		}

	}

	messagesString, _ := json.Marshal(messages)
	typesString, _ := json.Marshal(types)
	return messagesString, typesString, err
}
