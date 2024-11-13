package main

import (
	"fmt"
	"net"
)

// Ensures gofmt doesn't remove the "net" import in stage 1 (feel free to remove this!)
var _ = net.ListenUDP

// Header represents a DNS message header
type Header struct {
	ID      uint16 // 16 bits for query identifier
	Flags   uint16 // 16 bits for various flags
	QDCount uint16 // number of questions
	ANCount uint16 // number of answers
	NSCount uint16 // number of authority records
	ARCount uint16 // number of additional records
}

// NewHeader creates a new DNS header with default values
func NewHeader() Header {
	return Header{}
}

// SetQR sets the Query/Response flag (0 for query, 1 for response)
func (h *Header) SetQR(isResponse bool) {
	if isResponse {
		h.Flags |= (1 << 15)
	} else {
		h.Flags &^= (1 << 15)
	}
}

// ToBytes converts the header to its wire format representation
func (h *Header) ToBytes() []byte {
	bytes := make([]byte, 12)

	// ID (2 bytes)
	bytes[0] = byte(h.ID >> 8)
	bytes[1] = byte(h.ID)

	// Flags (2 bytes)
	bytes[2] = byte(h.Flags >> 8)
	bytes[3] = byte(h.Flags)

	// QDCount (2 bytes)
	bytes[4] = byte(h.QDCount >> 8)
	bytes[5] = byte(h.QDCount)

	// ANCount (2 bytes)
	bytes[6] = byte(h.ANCount >> 8)
	bytes[7] = byte(h.ANCount)

	// NSCount (2 bytes)
	bytes[8] = byte(h.NSCount >> 8)
	bytes[9] = byte(h.NSCount)

	// ARCount (2 bytes)
	bytes[10] = byte(h.ARCount >> 8)
	bytes[11] = byte(h.ARCount)

	return bytes
}

// FromBytes parses a byte slice into the header structure
func (h *Header) FromBytes(data []byte) error {
	if len(data) < 12 {
		return fmt.Errorf("header data too short: got %d bytes, want 12", len(data))
	}

	h.ID = uint16(data[0])<<8 | uint16(data[1])
	h.Flags = uint16(data[2])<<8 | uint16(data[3])
	h.QDCount = uint16(data[4])<<8 | uint16(data[5])
	h.ANCount = uint16(data[6])<<8 | uint16(data[7])
	h.NSCount = uint16(data[8])<<8 | uint16(data[9])
	h.ARCount = uint16(data[10])<<8 | uint16(data[11])

	return nil
}

func main() {
	// You can use print statements as follows for debugging, they'll be visible when running tests.
	fmt.Println("Logs from your program will appear here!")

	// Uncomment this block to pass the first stage
	//
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:2053")
	if err != nil {
		fmt.Println("Failed to resolve UDP address:", err)
		return
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("Failed to bind to address:", err)
		return
	}
	defer udpConn.Close()

	buf := make([]byte, 512)

	for {
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			break
		}

		receivedData := string(buf[:size])
		fmt.Printf("Received %d bytes from %s: %s\n", size, source, receivedData)

		header := NewHeader()

		if err := header.FromBytes(buf[:size]); err != nil {
			fmt.Println("Error parsing DNS header:", err)
			continue
		}

		// Create response header
		responseHeader := NewHeader()
		responseHeader.ID = header.ID // Use the same ID as the query
		responseHeader.SetQR(true)

		// Create an empty response
		response := responseHeader.ToBytes()

		_, err = udpConn.WriteToUDP(response, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
