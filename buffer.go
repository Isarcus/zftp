package zserver

import (
	"fmt"
	"net"
	"os"
	"strings"
	"zarks/system"
	"zarks/zmath"
	"zarks/zmath/encrypt"
)

// Buffer is a buffer for sending or receiving data
type Buffer struct {
	aes      encrypt.AES
	messages []Message

	isDone bool
}

// NewBuffer returns an empty buffer to which data can be appended
func NewBuffer(aes encrypt.AES) *Buffer {
	return &Buffer{
		aes:      aes,
		messages: []Message{},
		isDone:   false,
	}
}

// BufferFromPath reads in all data from the file at the specified path, and puts it into a Buffer
func BufferFromPath(path string, aes encrypt.AES, id uint32) (*Buffer, error) {
	// Open the file
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	// Obtain the filename
	filenameIdx := zmath.MaxInt(strings.LastIndexByte(path, '/'), strings.LastIndexByte(path, '\\'))
	filename := path[filenameIdx+1:]
	fmt.Println("Sending file: ", filename)

	// Initialize the Message array and append the StartMessage
	messages := make([]Message, 0, 3)
	messages = append(messages, NewStartMessage(id, filename))

	// Read filedata as some DataMessages
	var messageCt uint32 = 0 // counter for ensuring recipient can order messages correctly
	for {
		var chunk = make([]byte, LenPartData)
		n, _ := f.Read(chunk)
		if n == 0 {
			break
		}
		messages = append(messages, NewDataMessage(id, messageCt, chunk, uint32(n)))
		messageCt++
	}

	// Append the EndMessage
	messages = append(messages, NewEndMessage(id))

	return &Buffer{
		aes:      aes,
		messages: messages,
		isDone:   true,
	}, nil // my vscode extension won't let me format this nicely but oh well this works
}

// SendData encrypts and sends all of a Buffer's data to the desired IP address.
func (b *Buffer) SendData(ip string) {
	var (
		sendIP  = ip + PortSend
		checkIP = ip + PortCheck
	)

	// This will receive confirmation of a Message being sent
	ln, err := net.Listen("tcp", checkIP)
	if err != nil {
		fmt.Println("[LISTEN ERROR]", err)
	}

	for _, msg := range b.messages {
		received := make(chan bool)
		go func() { // I really love Go
			ln.Accept()
			received <- true
		}()

		// Dial TCP server
		conn, err := net.Dial("tcp", sendIP)
		if err != nil {
			fmt.Println("[DIAL ERROR]", err)
		}

		// Encrypt and write to TCP connection
		bytesWritten, err := conn.Write(Encrypt(msg, b.aes))
		if PrintConfirmation {
			fmt.Println("Bytes written:", bytesWritten)
		}
		if err != nil {
			fmt.Println("[SEND ERROR]", err)
		}

		// Wait for "ok" signal from receiving buffer
		_ = <-received
	}
	ln.Close()
}

// ReceiveData will make a buffer listen to the passed IP until it receives an EndMessage
func (b *Buffer) ReceiveData(ip string) {
	var (
		sendIP  = ip + PortSend
		checkIP = ip + PortCheck
	)
	ln, err := net.Listen("tcp", sendIP)
	if err != nil {
		fmt.Println(err)
	}
	for !b.isDone {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println(err)
		}

		msg := make([]byte, LenPartHeader+LenPartData)
		n, err := conn.Read(msg)
		if err != nil {
			fmt.Println(err)
		}

		if PrintConfirmation {
			fmt.Println("Bytes received: ", n)
		}

		b.ProcessData(msg)

		_, err = net.Dial("tcp", checkIP) // ready for next loop
		if err != nil {
			fmt.Println(err)
		}
	}
}

// ProcessData receives an encrypted Message as a byte slice and decodes its first LenPartHeader bytes.
func (b *Buffer) ProcessData(data []byte) {
	hdr := make([]byte, LenPartHeader)
	copy(hdr, data)
	hdr = encrypt.Decrypt(b.aes, hdr)

	var (
		id      = ReadUint32(hdr, 0)
		msgType = ReadUint32(hdr, 4)
	)

	switch MessageType(msgType) {
	case TypeData:
		msg := &DataMessage{
			id:       id,
			number:   ReadUint32(hdr, 8),
			valid:    ReadUint32(hdr, 12),
			filedata: data[LenPartHeader:],
		}
		b.messages = append(b.messages, msg)
		return
	case TypeStart:
		lenName := ReadUint32(hdr, 8)
		title := string(hdr[LenPartHeader-128 : LenPartHeader-128+lenName])

		msg := NewStartMessage(id, title)
		b.messages = append(b.messages, msg)
		return
	case TypeEnd:
		msg := NewEndMessage(id)
		b.messages = append(b.messages, msg)
		b.isDone = true
		return
	}
	fmt.Println("[ERROR] Could not read message!")
}

// Decrypt decrypts the filedata of each Messages of type TypeData
func (b *Buffer) Decrypt() {
	for _, msg := range b.messages {
		if msg.Type() == TypeData {
			msg.(*DataMessage).filedata = encrypt.Decrypt(b.aes, msg.(*DataMessage).filedata)
		}
	}
}

// IsDone returns whether the buffer has received an EndMessage
func (b *Buffer) IsDone() bool {
	return b.isDone
}

// Write will write the data in a Buffer to a file at the path specified by the passed stem,
// but will save at the address of the original filename
func (b *Buffer) Write(stem string) {
	if len(stem) != 0 {
		stem += "/"
	}
	path := stem + b.Name()

	f := system.CreateFile(path)
	defer f.Close()

	for _, msg := range b.messages {
		if msg.Type() == TypeData {
			data := msg.GetData()
			valid := msg.(*DataMessage).valid
			if valid == 0 {
				valid = LenPartData
			}
			f.Write(data[LenPartHeader : LenPartHeader+valid])
		}
	}
}

// Name returns the name of the file contained by the buffer
func (b *Buffer) Name() string {
	return string(b.messages[0].(*StartMessage).filename)
}

// Print prints all or some of a buffer's data
func (b *Buffer) Print(at ...int) {
	if len(at) == 0 {
		for _, msg := range b.messages {
			fmt.Println(msg.GetData())
		}
		return
	}

	for _, idx := range at {
		if idx < len(b.messages) {
			fmt.Println(b.messages[idx].GetData())
		}
	}
}
