package main

import (
	"fmt"
)

func ListInterfaces() {
	// devices, err := pcap.FindAllDevs()
	// if err != nil {
	// 	log.Fatalf("error retrieving devices - %v", err)
	// }

	// for _, device := range devices {
	// 	fmt.Printf("Device Name: %s\n", device.Name)
	// 	fmt.Printf("Device Description: %s\n", device.Description)
	// 	fmt.Printf("Device Flags: %d\n", device.Flags)
	// 	for _, iaddress := range device.Addresses {
	// 		fmt.Printf("\tInterface IP: %s\n", iaddress.IP)
	// 		fmt.Printf("\tInterface NetMask: %s\n", iaddress.Netmask)
	// 	}
	// 	fmt.Printf("=============================\n")
	// }
}

func dumpByteSlice(b []byte) {
	fmt.Printf("Begin dump\n")
	var a [16]byte
	var output string = ""

	n := (len(b) + 15) &^ 15
	for i := 0; i < n; i++ {
		if i%16 == 0 {
			output += fmt.Sprintf("%4d", i)
		}
		if i%8 == 0 {
			output += " "
		}
		if i < len(b) {
			output += fmt.Sprintf(" %02X", b[i])
		} else {
			output += "   "
		}
		if i >= len(b) {
			a[i%16] = ' '
		} else if b[i] < 32 || b[i] > 126 {
			a[i%16] = '.'
		} else {
			a[i%16] = b[i]
		}
		if i%16 == 15 {
			output += fmt.Sprintf("  %s\n", string(a[:]))
		}
	}
	fmt.Printf("%s\n", output)
}
