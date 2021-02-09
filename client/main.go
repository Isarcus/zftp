package main

import (
	"fmt"
	"zarks/system"
	"zarks/zmath/encrypt"
	"zserver"
)

func main() {
	var (
		r   = system.NewConsoleReader()
		err error
	)
	// Get IP
	ip := system.Query(r, "Please enter the desired IP address without port extension!")

	// Get cipher
	key := system.Query(r, "Please enter your 256-bit AES cipher key:")
	cipher := encrypt.NewAESCipher(key, encrypt.AES256)

	for {
		// Open the file
		var buf *zserver.Buffer
		for {
			path := system.Query(r, "Please enter the path to the file you would like to transfer.")
			buf, err = zserver.BufferFromPath(path, cipher, 0)
			if err == nil {
				break
			} else {
				fmt.Println(err)
			}
		}

		// Transfer the file
		buf.SendData(ip)

		if !system.QueryYN(r, "Another file?") {
			break
		}
	}
}
