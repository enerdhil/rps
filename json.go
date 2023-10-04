package main

import (
	"encoding/json"
	"fmt"
	"os"
)

type Message struct {
	Fields          []Field `json:"fields"`
	Name            string  `json:"name"`
	Namespace       string  `json:"namespace"`
	ProtocolID      int     `json:"protocolID"`
	Super           string  `json:"super"`
	SuperSerialize  bool    `json:"super_serialize"`
	Supernamespace  string  `json:"supernamespace"`
	UseHashFunction bool    `json:"use_hash_function"`
}

type Bounds struct {
	Low string `json:"low"`
	Up  string `json:"up"`
}

type Field struct {
	Bound                 Bounds `json:"bounds"`
	DefaultValue          string `json:"default_value"`
	Name                  string `json:"name"`
	Position              int    `json:"position"`
	Type                  string `json:"type"`
	WriteMethod           string `json:"write_method"`
	BooleanByteWrapperPos int    `json:"boolean_byte_wrapper_position,omitempty"`
	UseBooleanByteWrapper bool   `json:"use_boolean_byte_wrapper,omitempty"`
	IsVector              bool   `json:"is_vector,omitempty"`
	PrefixedByTypeID      bool   `json:"prefixed_by_type_id,omitempty"`
	SelfSerializeMethod   string `json:"self_serialize_method,omitempty"`
	TypeNamespace         string `json:"type_namespace,omitempty"`
	WriteLengthMethod     string `json:"write_length_method,omitempty"`
	WriteTypeIDMethod     string `json:"write_type_id_method,omitempty"`
}

func parse_json(jsonfile string) ([]Message, error) {
	jsonData, err := os.ReadFile(jsonfile)
	if err != nil {
		return nil, err
	}

	var messages []Message

	if err := json.Unmarshal([]byte(jsonData), &messages); err != nil {
		return nil, err
	}

	for _, message := range messages {
		fmt.Printf("Name: %s, Namespace: %s, ProtocolID: %d\n", message.Name, message.Namespace, message.ProtocolID)
		// Access other fields as needed
	}
	return messages, nil
}
