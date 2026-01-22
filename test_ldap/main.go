package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <ldap-server:port>")
		os.Exit(1)
	}

	server := os.Args[1]
	fmt.Printf("Connecting to %s...\n", server)

	conn, err := net.Dial("tcp", server)
	if err != nil {
		fmt.Printf("Failed to connect: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Println("Connected. Building RootDSE query...")

	// Build RootDSE search request
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 1, "MessageID"))

	searchRequest := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 3, nil, "Search Request")
	searchRequest.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Base DN"))
	searchRequest.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 2, "Scope (wholeSubtree)"))
	searchRequest.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 3, "Deref Aliases (derefAlways)"))
	searchRequest.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "Size Limit"))
	searchRequest.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "Time Limit"))
	searchRequest.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, false, "Types Only"))

	// Filter: (objectClass=*) - Present filter must be PRIMITIVE not CONSTRUCTED
	filter := ber.NewString(ber.ClassContext, ber.TypePrimitive, 7, "objectClass", "Present Filter")
	searchRequest.AppendChild(filter)

	// Attributes: supportedSASLMechanisms
	attributes := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
	attributes.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "supportedSASLMechanisms", "Attribute"))
	searchRequest.AppendChild(attributes)

	packet.AppendChild(searchRequest)

	// Print hex
	data := packet.Bytes()
	fmt.Printf("\nPacket hex (%d bytes):\n%s\n\n", len(data), hex.EncodeToString(data))

	// Print packet structure
	fmt.Println("Packet structure:")
	ber.PrintPacket(packet)

	fmt.Println("\nSending packet...")
	n, err := conn.Write(data)
	if err != nil {
		fmt.Printf("Failed to write: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Sent %d bytes\n", n)

	// Try to read response
	fmt.Println("Waiting for response...")
	buf := make([]byte, 4096)
	n, err = conn.Read(buf)
	if err != nil {
		fmt.Printf("Failed to read response: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Received %d bytes:\n%s\n", n, hex.EncodeToString(buf[:n]))
}
