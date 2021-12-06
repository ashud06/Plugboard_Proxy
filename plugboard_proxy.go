package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"golang.org/x/crypto/pbkdf2"
)

var (
	destination string
	port        string
	passwd      string
)

const (
	saltLength        int = 8
	aesKeyLength      int = 32
	dataHeaderLength  int = 2
	sock1BufferLength int = 4134
	stdBufferLength   int = 4096
)

func main() {

	listenPort := flag.String("l", "", "listenport")
	pwdFile := flag.String("p", "", "path to password file")

	flag.Parse()

	if *pwdFile == "" {
		log.Fatal("Please provide a file containing the password text with option -p\n")
	}
	file, err := os.Open(*pwdFile)
	defer file.Close()
	if err != nil {
		log.Fatal(err)
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		passwd = scanner.Text()
		break
	}

	var args = flag.Args()
	if len(args) != 2 {
		log.Fatal("Args expected: 'destination port'\n")
	}

	destination = args[0]
	port = args[1]

	if *listenPort == "" {
		clientHandler()
	} else {
		reverseProxyHandler(*listenPort)
	}

}

func prependLengthBytes(data []byte) []byte {
	lengthHeader := make([]byte, dataHeaderLength)
	dataLength := uint16(len(data) + dataHeaderLength)
	binary.BigEndian.PutUint16(lengthHeader, dataLength)
	return append(lengthHeader, data...)
}

func encrypt(plaintext []byte) []byte {
	salt := make([]byte, saltLength)
	rand.Read(salt)
	aesKey := pbkdf2.Key([]byte(passwd), salt, 1000, aesKeyLength, sha256.New)

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		log.Fatal(err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal(err)
	}

	nonce := make([]byte, aesgcm.NonceSize())
	rand.Read(nonce)

	data := append(salt, nonce...)
	encryptedData := aesgcm.Seal(data, nonce, plaintext, nil)

	return encryptedData
}

func decrypt(data []byte) []byte {
	salt := data[:saltLength]
	aesKey := pbkdf2.Key([]byte(passwd), salt, 1000, aesKeyLength, sha256.New)

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		log.Fatal(err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal(err)
	}

	nonceSize := aesgcm.NonceSize()
	nonce := data[saltLength : nonceSize+saltLength]
	encryptedData := data[nonceSize+saltLength:]

	plaintext, err := aesgcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		log.Fatal(err)
	}

	return plaintext
}

func handleEqualCase(buffer []byte,reader *bufio.Reader,readSize int,startIdx int)([]byte,int,bool){
	b, err := reader.ReadByte()
	var err_flag bool
	if err == nil {
		buffer = append(buffer, b)
		readSize = readSize + 1
	} else {
		log.Println("Error while reading the 2nd length byte", err)
		err_flag=true
	}
	return buffer,readSize,err_flag
}

func handleGreaterCase(buffer []byte,writer *bufio.Writer,startIdx int,dataLength int) (*bufio.Writer,int,bool){
	var err_flag bool
	decryptedData := decrypt(buffer[startIdx+dataHeaderLength : startIdx+dataLength])
	_, err := writer.Write(decryptedData)
	if err != nil {
		log.Println("Error while writing:", err)
		err_flag=true
	}
	writer.Flush()
	startIdx = startIdx + dataLength
	return writer,startIdx,err_flag
}

func handleLesserCase(buffer []byte, readSize int,dataLength int, startIdx int, reader *bufio.Reader, writer *bufio.Writer)(*bufio.Writer,int,[]byte,bool){
	var err_flag bool
	remBuffer := make([]byte, dataLength-readSize+startIdx)
	if n, err := io.ReadFull(reader, remBuffer); err == nil {
		decryptedData := decrypt(append(buffer[startIdx+dataHeaderLength:readSize], remBuffer[:n]...))
		_, err := writer.Write(decryptedData)
		if err != nil {
			err_flag=true
			log.Println("Error while writing:", err)
		}
		writer.Flush()
		startIdx = readSize
	} else {
		err_flag=true
		log.Println(err)
	}
	return writer,startIdx,buffer,err_flag
}

func handleEncryptedData(buffer []byte, readSize int, reader *bufio.Reader, writer *bufio.Writer) {
	var startIdx int = 0
	var err_flag bool
	for startIdx < readSize {
		if startIdx == readSize-1 {
			buffer,readSize,err_flag= handleEqualCase(buffer,reader,readSize,startIdx)
			if err_flag {
				break
			}
		}
		lenHeader := buffer[startIdx : startIdx+dataHeaderLength]
		dataLength := int(binary.BigEndian.Uint16(lenHeader))
		if readSize-startIdx >= dataLength {
			writer,startIdx,err_flag=handleGreaterCase(buffer,writer,startIdx,dataLength)
			if err_flag{
				break
			}
		} else if readSize-startIdx < dataLength {
			writer,startIdx,buffer,err_flag=handleLesserCase(buffer,readSize,dataLength,startIdx,reader,writer)
			if err_flag{
				break
			}
		}
	}
}

func clientHandler() {
	stdinReader := bufio.NewReader(os.Stdin)
	stdoutWriter := bufio.NewWriter(os.Stdout)

	addr, err := net.ResolveTCPAddr("tcp", destination+":"+port)
	if err != nil {
		log.Fatal(err)
	}

	conn, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	conn.SetReadBuffer(sock1BufferLength)
	conn.SetWriteBuffer(sock1BufferLength)

	connReader := bufio.NewReaderSize(conn, sock1BufferLength)
	if n := connReader.Buffered(); n > 0 {
		connReader.Discard(n)
	}
	connWriter := bufio.NewWriterSize(conn, sock1BufferLength)

	go clientHelper(connReader,stdoutWriter)

	for {
		stdinData := make([]byte, stdBufferLength)
		if n, err := stdinReader.Read(stdinData); err == nil {
			encryptedData := encrypt(stdinData[:n])
			data := prependLengthBytes(encryptedData)
			_, err := connWriter.Write(data)
			if err != nil {
				log.Println("Error while writing to pbproxy server:", err)
				return
			}
			connWriter.Flush()
		} else {
			//log.Println("stdin read error", err)
			break
		}
	}
}

func clientHelper(connReader *bufio.Reader,stdoutWriter *bufio.Writer){
	for {
		serverData := make([]byte, sock1BufferLength)
		if n, err := connReader.Read(serverData); err == nil {
			handleEncryptedData(serverData[:n], n, connReader, stdoutWriter)
		} else {
			//log.Println("read from server error", err)
			break
		}
	}
}

func connectionHandler(clientConn *net.TCPConn) {
	serviceConn, err := net.Dial("tcp", destination+":"+port)
	defer serviceConn.Close()
	if err != nil {
		log.Println("Error connecting to the service at", destination+":"+port, err)
		return
	}

	serviceReader := bufio.NewReader(serviceConn)
	if n := serviceReader.Buffered(); n > 0 {
		serviceReader.Discard(n)
	}
	serviceWriter := bufio.NewWriter(serviceConn)

	clientReader := bufio.NewReaderSize(clientConn, sock1BufferLength)
	clientWriter := bufio.NewWriterSize(clientConn, sock1BufferLength)
	go serverHelper(serviceReader,clientWriter)

	for {
		clientData := make([]byte, sock1BufferLength)
		if n, err := clientReader.Read(clientData); err == nil {
			handleEncryptedData(clientData[:n], int(n), clientReader, serviceWriter)
		} else {
			//           log.Println("read from client error", err)
			break
		}
	}
}
func serverHelper(serviceReader *bufio.Reader,clientWriter *bufio.Writer) {
	for {
		serviceData := make([]byte, stdBufferLength)
		if n, err := serviceReader.Read(serviceData); err == nil {
			encryptedServiceData := encrypt(serviceData[:n])
			data := prependLengthBytes(encryptedServiceData)
			_, err := clientWriter.Write(data)
			if err != nil {
				log.Println("Error while writing to pbproxy client:", err)
				return
			}
			clientWriter.Flush()
		} else {
			//               log.Println("read from service error", err)
			break
		}
	}
}

func reverseProxyHandler(port string) {
	addr, err := net.ResolveTCPAddr("tcp", ":"+port)
	if err != nil {
		log.Fatal(err)
	}

	ln, err := net.ListenTCP("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Listening on port", port)

	for {
		conn, err := ln.AcceptTCP()
		if err != nil {
			log.Fatal(err)
		}
		defer conn.Close()

		conn.SetReadBuffer(sock1BufferLength)
		conn.SetWriteBuffer(sock1BufferLength)

		go connectionHandler(conn)
	}
}
