package main

import (
	"net"
	"zarks/system"
	"zarks/zmath/encrypt"
	"zserver"
)

func main() {
	var (
		r  = system.NewConsoleReader()
		ip string
	)

	for {
		ip = system.Query(r, "What is the IP of file sender? (Do not enter port extensions like :25565)")
		if len(ip) == 0 {
			ip = zserver.Local
		}
		if system.QueryYN(r, "Please confirm that "+ip+" is the desired sender.") {
			break
		}
	}

	key := system.Query(r, "Please enter your 256-bit AES cipher key:")
	cipher := encrypt.NewAESCipher(key, encrypt.AES256)
	buf := zserver.NewBuffer(cipher)

	buf.ReceiveData(ip)

	buf.Decrypt()

	buf.Write("")
}

func receive(conn net.Conn, buf *zserver.Buffer) {
	bytes := make([]byte, zserver.LenPartHeader+zserver.LenPartData)
	conn.Read(bytes)
	buf.ProcessData(bytes)
	if buf.IsDone() {
		net.Dial("tcp", zserver.Local+zserver.PortSend) // this will cause a new loop iteration and the file will save
	}
}
