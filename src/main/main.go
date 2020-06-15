package main

import (
	"aes"
	"bufio"
	"fmt"
	"os"
)

func main() {
	startBanner()
	callSimpleAESTest()
	// Program does not close until the enter is entered.
	fmt.Scanln()
}
func startBanner() {
	fmt.Printf("%s", "Start AES Test Program...Welcome!\n")
}
func callSimpleAESTest() {
	plainText := make([]byte, 160) // possible 160 characters
	key := make([]byte, 16)
	decryptKey := make([]byte, 32)

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter Plain Text: ")
	stringText, _ := reader.ReadString('\n')
	copy(plainText, []byte(stringText))

	fmt.Print("Enter Encryption Key: ")
	stringKey, _ := reader.ReadString('\n')
	copy(key, []byte(stringKey))

	fmt.Print("Enter Decryption Key: ")
	stringDecryptKey, _ := reader.ReadString('\n')
	copy(decryptKey, []byte(stringDecryptKey))

	fmt.Printf("\n%s\n", "------------------------------------------")
	fmt.Println("CBC Mode Result : ")
	aes.EncryptCbcMode(plainText, key)
	aes.DecryptCbcMode(decryptKey)

	fmt.Printf("\n%s\n", "------------------------------------------")
	fmt.Println("CTR Mode Result : ")
	aes.EncryptCtrMode(plainText, key)
	aes.DecryptCtrMode(decryptKey)
}
