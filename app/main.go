package main

import (
	"fmt"
	"net"
	"strings"
)

// Header represents a DNS message header
type Header struct {
	ID      uint16 // 16 bits for query identifier
	Flags   uint16 // 16 bits for various flags
	QDCount uint16 // number of questions
	ANCount uint16 // number of answers
	NSCount uint16 // number of authority records
	ARCount uint16 // number of additional records
}

// Question represents a DNS question section
type Question struct {
	Name  string // domain name
	Type  uint16 // query type
	Class uint16 // query class
}

// encodeDNSName converts a domain name to DNS wire format
func encodeDNSName(name string) []byte {
	var encoded []byte
	if name == "" {
		return []byte{0}
	}

	labels := strings.Split(name, ".")
	for _, label := range labels {
		encoded = append(encoded, byte(len(label)))
		encoded = append(encoded, []byte(label)...)
	}
	encoded = append(encoded, 0) // terminating byte
	return encoded
}

// decodeDNSName extracts a domain name from DNS wire format
func decodeDNSName(data []byte, offset int) (string, int, error) {
	var name []string
	pos := offset

	for pos < len(data) {
		length := int(data[pos])
		if length == 0 {
			pos++
			break
		}

		if pos+1+length > len(data) {
			return "", 0, fmt.Errorf("invalid DNS name format")
		}

		name = append(name, string(data[pos+1:pos+1+length]))
		pos += 1 + length
	}

	return strings.Join(name, "."), pos - offset, nil
}

// NewHeader creates a new DNS header with default values
func NewHeader() Header {
	return Header{
		ID: 1234, // Set default ID to 1234
	}
}

// ToBytes converts the Question to wire format
func (q *Question) ToBytes() []byte {
	var bytes []byte

	// Encode domain name
	bytes = append(bytes, encodeDNSName(q.Name)...)

	// Type (2 bytes)
	bytes = append(bytes, byte(q.Type>>8), byte(q.Type))

	// Class (2 bytes)
	bytes = append(bytes, byte(q.Class>>8), byte(q.Class))

	return bytes
}

// FromBytes parses a byte slice into the Question structure
func (q *Question) FromBytes(data []byte, offset int) (int, error) {
	var err error
	var nameLen int

	// Decode domain name
	q.Name, nameLen, err = decodeDNSName(data[offset:], 0)
	if err != nil {
		return 0, err
	}

	offset += nameLen
	if offset+4 > len(data) {
		return 0, fmt.Errorf("question data too short")
	}

	// Extract Type and Class
	q.Type = uint16(data[offset])<<8 | uint16(data[offset+1])
	q.Class = uint16(data[offset+2])<<8 | uint16(data[offset+3])

	return nameLen + 4, nil
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

		// Parse question section
		question := Question{}
		_, err = question.FromBytes(buf[12:size], 0) // 12 is the size of the header
		if err != nil {
			fmt.Println("Error parsing DNS question:", err)
			continue
		}

		// Create response header
		responseHeader := NewHeader()
		responseHeader.ID = header.ID // Use the same ID as the query
		responseHeader.SetQR(true)
		responseHeader.QDCount = 1 // We have one question

		// Create response with both header and question
		response := responseHeader.ToBytes()
		response = append(response, question.ToBytes()...)

		_, err = udpConn.WriteToUDP(response, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
