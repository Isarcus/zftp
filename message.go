package zserver

import (
	"zarks/zmath"
	"zarks/zmath/encrypt"
	"zarks/zmath/zbits"
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

		bytesID      = zbits.Uint32ToBytes(msg.id, zbits.LE)
		bytesType    = zbits.Uint32ToBytes(uint32(msg.Type()), zbits.LE)
		bytesNameLen = zbits.Uint32ToBytes(uint32(len(msg.filename)), zbits.LE)
	)

	copy(data[0:4], bytesID)                // bytes 0-3: the ID of the message
	copy(data[4:8], bytesType)              // bytes 4-7: the type of the message
	copy(data[8:12], bytesNameLen)          // bytes 8-11: the length of the filename
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
	filedata []byte
	valid    uint32 // how many bytes of the filedata are actual data (leave as 0 for full messages)
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

		bytesID     = zbits.Uint32ToBytes(msg.id, zbits.LE)
		bytesType   = zbits.Uint32ToBytes(uint32(msg.Type()), zbits.LE)
		bytesNumber = zbits.Uint32ToBytes(msg.number, zbits.LE)
		bytesValid  = zbits.Uint32ToBytes(uint32(msg.valid), zbits.LE)
	)

	copy(data[0:4], bytesID)      // bytes 0-3: the ID of the message
	copy(data[4:8], bytesType)    // bytes 4-7: the type of the message
	copy(data[8:12], bytesNumber) // bytes 8-11: the order of the message for files > 16KB (most files)
	copy(data[12:16], bytesValid) // bytes 12-15: how many bytes of the filedata are to be used

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

		bytesID   = zbits.Uint32ToBytes(msg.id, zbits.LE)
		bytesType = zbits.Uint32ToBytes(uint32(msg.Type()), zbits.LE)
	)

	copy(data[0:4], bytesID)   // bytes 0-3: the ID of the message
	copy(data[4:8], bytesType) // bytes 4-7: the type of the message

	return data
}
