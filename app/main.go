package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"golang.org/x/net/context"
	"log"
	"net"
	"strings"
	"time"
)

// DNSHeader represents a DNS message header
type DNSHeader struct {
	ID      uint16 // Packet Identifier (16 bits)
	Flags   uint16 // Flags (16 bits) - contains multiple sub-fields
	QDCOUNT uint16 // Number of Question Records
	ANCOUNT uint16 // Number of Answer Records
	NSCOUNT uint16 // Number of Authority Records
	ARCOUNT uint16 // Number of Additional Records
}

// Serialize serializes the DNSHeader into a byte array
func (h *DNSHeader) Serialize() []byte {
	buf := make([]byte, 12) // DNS header is always 12 bytes long
	binary.BigEndian.PutUint16(buf[0:2], h.ID)
	binary.BigEndian.PutUint16(buf[2:4], h.Flags)
	binary.BigEndian.PutUint16(buf[4:6], h.QDCOUNT)
	binary.BigEndian.PutUint16(buf[6:8], h.ANCOUNT)
	binary.BigEndian.PutUint16(buf[8:10], h.NSCOUNT)
	binary.BigEndian.PutUint16(buf[10:12], h.ARCOUNT)
	return buf
}

// Parse parses a byte array into a DNSHeader struct
func (h *DNSHeader) Parse(data []byte) {
	h.ID = binary.BigEndian.Uint16(data[0:2])
	h.Flags = binary.BigEndian.Uint16(data[2:4])
	h.QDCOUNT = binary.BigEndian.Uint16(data[4:6])
	h.ANCOUNT = binary.BigEndian.Uint16(data[6:8])
	h.NSCOUNT = binary.BigEndian.Uint16(data[8:10])
	h.ARCOUNT = binary.BigEndian.Uint16(data[10:12])
}

type DNSQuestion struct {
	Name  string
	Type  uint16
	Class uint16
}

func (q *DNSQuestion) Serialize() []byte {
	var buf []byte
	labels := strings.Split(q.Name, ".")
	for _, label := range labels {
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}
	buf = append(buf, 0)

	qType := make([]byte, 2)
	binary.BigEndian.PutUint16(qType, q.Type)
	buf = append(buf, qType...)

	class := make([]byte, 2)
	binary.BigEndian.PutUint16(class, q.Class)
	buf = append(buf, class...)

	return buf
}

type DNSAnswer struct {
	Name     string
	Type     uint16
	Class    uint16
	TTL      uint32
	RDLength uint16
	RData    []byte
}

func (a *DNSAnswer) Serialize() []byte {
	var buf []byte

	labels := strings.Split(a.Name, ".")
	for _, label := range labels {
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}
	buf = append(buf, 0)

	typeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(typeBytes, a.Type)
	buf = append(buf, typeBytes...)

	classBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(classBytes, a.Class)
	buf = append(buf, classBytes...)

	ttlBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(ttlBytes, a.TTL)
	buf = append(buf, ttlBytes...)

	rdLengthBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(rdLengthBytes, a.RDLength)
	buf = append(buf, rdLengthBytes...)

	buf = append(buf, a.RData...)

	return buf
}

// Create a new DNS reply message based on the specified values
func createDNSReply(header DNSHeader, questions []DNSQuestion, answers []DNSAnswer) []byte {
	// Construct the 16-bit Flags field
	// | QR  | OPCODE |  AA | TC | RD | RA | Z   | RCODE |
	// |  1  | 0000   |  1  |  0 |  0 |  0 | 000 | 0000  |
	// ---------------------------------------------------
	//  16-15  14-11    10    9    8    7    6-4   3-0
	// ---------------------------------------------------
	// QR = 1
	// OPCODE = 0 (0000)
	// AA = 1
	// TC = 0
	// RD = 0
	// RA = 0
	// Z = 0 (000)
	// RCODE = 0 (0000)
	// ---------------------------------------------------
	// 1000 0000 0000 0000  (QR << 15)
	// OR 0000 0000 0000 0000  (OPCODE << 11)
	// OR 0000 0100 0000 0000  (AA << 10)
	// OR 0000 0000 0000 0000  (TC << 9)
	// OR 0000 0000 0000 0000  (RD << 8)
	// OR 0000 0000 0000 0000  (RA << 7)
	// OR 0000 0000 0000 0000  (RCODE)
	// = 1000 0100 0000 0000 (combined)
	flags := (1 << 15) | // QR bit (1 bit)
		(header.Flags & 0x7800) | // OPCODE (4 bits) - mask: 0111 1000 0000 0000
		(header.Flags & 0x0400) | // AA bit (1 bit) - mask: 0000 0100 0000 0000
		(0 << 9) | // TC bit (1 bit)
		(header.Flags & 0x0100) | // RD bit (1 bit) - mask: 0000 0001 0000 0000
		(1 << 7) | // RA bit (1 bit)
		(uint16(4) & 0x00FF) // RCODE (4 bits)

	replyHeader := &DNSHeader{
		ID:      header.ID,
		Flags:   flags,
		QDCOUNT: header.QDCOUNT,
		ANCOUNT: uint16(len(answers)),
		NSCOUNT: 0,
		ARCOUNT: 0,
	}

	var questionsBinary []byte
	for _, question := range questions {
		questionsBinary = append(questionsBinary, question.Serialize()...)
	}

	var answersBinary []byte
	for _, answer := range answers {
		answersBinary = append(answersBinary, answer.Serialize()...)
	}

	return append(append(replyHeader.Serialize(), questionsBinary...), answersBinary...)
}

func parseName(data []byte, offset int) (string, int, error) {
	var nameParts []string

	for {
		if offset >= len(data) {
			log.Printf("parseName: offset %d out of bounds (data length %d)", offset, len(data))
			return "", 0, fmt.Errorf("offset out of bounds")
		}

		labelLength := int(data[offset])
		if labelLength == 0 {
			offset++
			break
		}

		nameParts = append(nameParts, string(data[offset+1:offset+1+labelLength]))
		offset += 1 + labelLength
	}

	name := strings.Join(nameParts, ".")
	return name, offset, nil
}

func decompressQuestions(data []byte) []byte {
	decompressedData := make([]byte, 0, len(data))
	for i := 0; i < len(data); i++ {
		// checks if question is compressed
		// 0xC0 == 11000000 -> https://www.rfc-editor.org/rfc/rfc1035#section-4.1.4
		// if first two bits are 1, then question is compressed and the following offset is
		// a pointer to a previous position
		if data[i] != 0xC0 {
			decompressedData = append(decompressedData, data[i])
			continue
		}

		// This part deals with the compression pointer
		// 0xC0 is a pointer indicating the next byte is part of the pointer address
		pointer := binary.BigEndian.Uint16(data[i : i+2])
		// Logical AND to strip first two bits (0x3FFF = 0011111111111111)
		pointerValue := int(pointer & 0x3FFF)
		// Adjust because the pointer is relative to the start of the DNS packet header
		pointerValue -= 12
		// Resolve the pointer by copying the pointed-to name into decompressedData
		for j := pointerValue; j < len(data); j++ {
			if data[j] == 0x00 {
				// End of the compressed name
				decompressedData = append(decompressedData, data[j])
				// Skip the next byte as it was part of the pointer
				i += 1
				break
			}
			// Add decompressed byte by byte
			decompressedData = append(decompressedData, data[j])
		}
	}
	return decompressedData
}

func parseDNSQuestions(data []byte, header DNSHeader) ([]DNSQuestion, error) {
	expandedData := decompressQuestions(data)
	questions := make([]DNSQuestion, header.QDCOUNT)
	offset := 0

	for i := range questions {
		var question DNSQuestion
		var err error

		question.Name, offset, err = parseName(expandedData, offset)
		if err != nil {
			return questions, err
		}

		if len(expandedData) < offset+4 {
			return questions, fmt.Errorf("invalid question format")
		}

		question.Type = binary.BigEndian.Uint16(expandedData[offset : offset+2])
		offset += 2
		question.Class = binary.BigEndian.Uint16(expandedData[offset : offset+2])
		offset += 2

		questions[i] = question
	}
	return questions, nil
}

func handleDNSRequest(conn *net.UDPConn, addr *net.UDPAddr, data []byte, resolverAddr string) {
	// Log the received packet
	log.Printf("Received DNS query from %s with data: %v", addr.String(), data)

	var header DNSHeader
	header.Parse(data)
	log.Printf("Parsed DNS header: %+v", header)

	// Parse the incoming DNS questions
	questions, err := parseDNSQuestions(data[12:], header) // Skip the first 12 bytes (DNS header)
	if err != nil {
		log.Printf("Failed to parse DNS question: %v", err)
		return
	}

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Millisecond * time.Duration(10000),
			}
			return d.DialContext(ctx, network, resolverAddr)
		},
	}

	log.Printf("Parsed DNS questions: %+v", questions)

	answers := make([]DNSAnswer, len(questions))
	for i, question := range questions {
		ips, err := resolver.LookupIP(context.Background(), "ip4", question.Name)
		if err != nil {
			continue
		}
		ip := ips[0].To4()

		// Construct a sample answer
		answers[i] = DNSAnswer{
			Name:     question.Name,
			Type:     1, // A record
			Class:    1, // IN (Internet)
			TTL:      60,
			RDLength: 4,
			RData:    []byte{ip[0], ip[1], ip[2], ip[3]},
		}
	}

	log.Printf("Constructed DNS answers: %+v", answers)

	reply := createDNSReply(header, questions, answers)

	log.Printf("Sending DNS reply to %s with ID: %d", addr.String(), header.ID)

	_, err = conn.WriteToUDP(reply, addr)
	if err != nil {
		log.Printf("Failed to send DNS reply: %v", err)
		return
	}

	log.Printf("Sent DNS reply to %s", addr.String())
}

func main() {
	resolverAddr := flag.String("resolver", "", "Address of the DNS resolver to forward queries to in form <ip>:<port>")
	flag.Parse()

	if *resolverAddr == "" {
		log.Fatalf("resolver address is required")
	}

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

	log.Printf("DNS forwarder running on %s, forwarding to %s", udpAddr, *resolverAddr)

	for {
		buf := make([]byte, 512) // DNS messages are usually limited to 512 bytes
		n, addr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("Failed to read UDP packet: %v", err)
			continue
		}

		go handleDNSRequest(udpConn, addr, buf[:n], *resolverAddr)
	}
}
