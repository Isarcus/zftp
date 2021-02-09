package zserver

import (
	"encoding/binary"
	"zarks/zmath"
	"zarks/zmath/encrypt"
)

// Message is a package of information that can be transmitted
type Message interface {
	Type() MessageType // Type returns the MessageType of a message.
	GetData() []byte   // GetData returns a message's data, formatted and ready to transmit over tcp.
}

// Encrypt returns a slice of a Message's encrypted data.
func Encrypt(msg Message, aes encrypt.AES) []byte {
	return encrypt.Encrypt(aes, msg.GetData())
}

// Decrypt returns a slice of a Message's decrypted data.
func Decrypt(msg Message, aes encrypt.AES) []byte {
	return encrypt.Decrypt(aes, msg.GetData())
}

//                   //
// - - - START - - - //
//                   //

// StartMessage is a message that initiates a file transfer.
type StartMessage struct {
	id       uint32
	filename []byte
}

// NewStartMessage returns a Message that initiates a file transfer.
func NewStartMessage(ID uint32, filename string) Message {
	nameLen := zmath.MinInt(128, len(filename))

	return &StartMessage{
		id:       ID,
		filename: []byte(filename)[:nameLen],
	}
}

// Type returns TypeStart for a StartMessage
func (msg *StartMessage) Type() MessageType {
	return TypeStart
}

// GetData returns a StartMessage's data in a byte slice.
func (msg *StartMessage) GetData() []byte {
	var (
		data = make([]byte, LenStart)

		msgType = uint32(msg.Type())
		nameLen = uint32(len(msg.filename))
	)

	PutUint32(msg.id, data, posID)          // bytes 0-3: the ID of the message
	PutUint32(msgType, data, posType)       // bytes 4-7: the type of the message
	PutUint32(nameLen, data, posNameLen)    // bytes 8-11: the length of the filename
	copy(data[LenStart-128:], msg.filename) // the last 128 bytes: the filename

	return data
}

//                  //
// - - - DATA - - - //
//                  //

// DataMessage is a message for transferring data
type DataMessage struct {
	id       uint32
	number   uint32
	valid    uint32 // how many bytes of the filedata are actual data (leave as 0 for full messages)
	filedata []byte
}

// NewDataMessage returns a Message for transferring file data
func NewDataMessage(id uint32, number uint32, data []byte, valid uint32) Message {
	filedata := make([]byte, LenPartData)
	copy(filedata, data)
	return &DataMessage{
		id:       id,
		number:   number,
		filedata: data,
		valid:    valid,
	}
}

// Type returns TypeData for a DataMessage
func (msg *DataMessage) Type() MessageType {
	return TypeData
}

// GetData returns all of a DataMessage's data (including the header) in one slice
func (msg *DataMessage) GetData() []byte {
	var (
		data = make([]byte, LenPartHeader+LenPartData)

		msgType = uint32(msg.Type())
	)

	PutUint32(msg.id, data, posID)       // bytes 0-3: the ID of the message
	PutUint32(msgType, data, posType)    // bytes 4-7: the type of the message
	PutUint32(msg.number, data, posNum)  // bytes 8-11: the order of the message for files > 16KB (most files)
	PutUint32(msg.valid, data, posValid) // bytes 12-15: how many bytes of the filedata are to be used

	copy(data[LenPartHeader:], msg.filedata) // last [LenDataPart] bytes: the actual filedata

	return data
}

//                 //
// - - - END - - - //
//                 //

// EndMessage is a Message that terminates a file transfer
type EndMessage struct {
	id uint32
}

// NewEndMessage returns a Message that terminates a file transfer
func NewEndMessage(id uint32) Message {
	return &EndMessage{
		id: id,
	}
}

// Type returns TypeEnd for an EndMessage
func (msg *EndMessage) Type() MessageType {
	return TypeEnd
}

// GetData returns an EndMessage's data in a byte slice.
func (msg *EndMessage) GetData() []byte {
	var (
		data = make([]byte, LenEnd)

		msgType = uint32(msg.Type())
	)

	PutUint32(msg.id, data, posID)    // bytes 0-3: the ID of the message
	PutUint32(msgType, data, posType) // bytes 4-7: the type of the message

	return data
}

//                   //
// - - - BYTES - - - //
//                   //

// ReadUint16 reads a uint16 from some data at the target location
func ReadUint16(data []byte, at int) uint16 {
	return binary.LittleEndian.Uint16(data[at : at+2])
}

// ReadUint32 reads a uint32 from some data at the target location
func ReadUint32(data []byte, at int) uint32 {
	return binary.LittleEndian.Uint32(data[at : at+4])
}

// ReadUint64 reads a uint64 from some data at the target location
func ReadUint64(data []byte, at int) uint64 {
	return binary.LittleEndian.Uint64(data[at : at+8])
}

// PutUint16 writes a uint16 to some data at the target location
func PutUint16(num uint16, data []byte, at int) {
	binary.LittleEndian.PutUint16(data[at:at+2], num)
}

// PutUint32 writes a uint16 to some data at the target location
func PutUint32(num uint32, data []byte, at int) {
	binary.LittleEndian.PutUint32(data[at:at+4], num)
}

// PutUint64 writes a uint16 to some data at the target location
func PutUint64(num uint64, data []byte, at int) {
	binary.LittleEndian.PutUint64(data[at:at+8], num)
}
