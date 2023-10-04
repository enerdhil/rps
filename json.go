package main

import (
	"encoding/json"
	"fmt"
	"os"
)

type Messages struct {
	Messages []Message `json:"messages,omitempty"`
}

type Message struct {
	Fields          []Field `json:"fields,omitempty"`
	Name            string  `json:"name,omitempty"`
	Namespace       string  `json:"namespace,omitempty"`
	ProtocolID      int     `json:"protocolID,omitempty"`
	Super           string  `json:"super,omitempty"`
	SuperSerialize  bool    `json:"super_serialize,omitempty"`
	Supernamespace  string  `json:"supernamespace,omitempty"`
	UseHashFunction bool    `json:"use_hash_function,omitempty"`
}

type Bounds struct {
	Low string `json:"low,omitempty"`
	Up  string `json:"up,omitempty"`
}

type Field struct {
	Bound                 Bounds `json:"bounds,omitempty"`
	DefaultValue          string `json:"default_value,omitempty"`
	Name                  string `json:"name,omitempty"`
	Position              int    `json:"position,omitempty"`
	Type                  string `json:"type,omitempty"`
	WriteMethod           string `json:"write_method,omitempty"`
	BooleanByteWrapperPos int    `json:"boolean_byte_wrapper_position,omitempty"`
	UseBooleanByteWrapper bool   `json:"use_boolean_byte_wrapper,omitempty"`
	IsVector              bool   `json:"is_vector,omitempty"`
	PrefixedByTypeID      bool   `json:"prefixed_by_type_id,omitempty"`
	SelfSerializeMethod   string `json:"self_serialize_method,omitempty"`
	TypeNamespace         string `json:"type_namespace,omitempty"`
	WriteLengthMethod     string `json:"write_length_method,omitempty"`
	WriteTypeIDMethod     string `json:"write_type_id_method,omitempty"`
}

func parse_json(jsonfile string) (Messages, error) {
	var messages Messages
	jsonData, err := os.ReadFile(jsonfile)
	if err != nil {
		return messages, err
	}

	if err := json.Unmarshal([]byte(jsonData), &messages); err != nil {
		return messages, err
	}

	for _, message := range messages.Messages {
		fmt.Printf("Name: %s, Namespace: %s, ProtocolID: %d\n", message.Name, message.Namespace, message.ProtocolID)
		// Access other fields as needed
	}
	return messages, nil
}
