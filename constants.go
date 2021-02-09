package zserver

const (
	// PortSend is the port used to send data
	PortSend = ":31415"

	// PortCheck is the port used to check message integrity
	PortCheck = ":31416"

	// Local is just the local machine IP
	Local = "127.0.0.1"
)

// MessageType is used in a message header for identifying what kind of message it is
type MessageType uint32

const (
	// TypeStart should initiate a message
	TypeStart MessageType = iota
	// TypeData is what's used for actually transferring filedata
	TypeData
	// TypeEnd should terminate a message
	TypeEnd
)

const (
	// KB is the size of a kilobyte
	KB = 1024

	// LenStart is the length of a StartMessage's data
	LenStart = 256
	// LenEnd is the length of an EndMessage's data
	LenEnd = 256
	// LenPartHeader is the length of the header of a DataMessage
	LenPartHeader = 256
	// LenPartData is the length of the filedata of a DataMessage
	LenPartData = 16 * KB
)

/*
HEADER STRUCTURE:

0:4    |  00 00 00 00  |  ID of file
4:8    |  00 00 00 00  |  MessageType
8:12   |  00 00 00 00  |  Number (TypeData only), OR Length of filename in bytes (TypeStart only)
12:16  |  00 00 00 00  |  Valid bytes (TypeData only)

...

Last 128 bytes are for filename (TypeStart only)

*/
