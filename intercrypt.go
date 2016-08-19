package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"

	"golang.org/x/crypto/nacl/secretbox"

	"gx/ipfs/QmT8rehPR3F6bmwL6zjUN8XpiDBFFpMP2myPdC6ApsWfJf/go-base58"

	"github.com/ipfs/go-ipfs-api"
	"github.com/ipfs/go-ipfs/merkledag"
	"github.com/ipfs/go-ipfs/unixfs"
)

func main() {
	flag.Parse()
	switch flag.Arg(0) {
	case "add":
		key, secret, err := AddCommand(flag.Arg(1))
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Printf("Key: %s\n", key)
		fmt.Printf("Secret: %s\n", secret)
	case "get":
		err := GetCommand(flag.Arg(1), flag.Arg(2))
		if err != nil {
			fmt.Println(err)
			return
		}
	default:
		fmt.Print(`NAME:
  intercrypt - Store encrypted files on IPFS

USAGE:
  intercrypt add <filename>
  intercrypt get <key> <secret>

`)
	}
}

func AddCommand(filename string) (string, string, error) {
	// Generate secret key
	key, err := NewKey()
	if err != nil {
		return "", "", err
	}
	// Read file
	filedata, err := ioutil.ReadFile(filename)
	if err != nil {
		return "", "", err
	}
	// Wrap in unixfs Node
	fsnode := new(unixfs.FSNode)
	fsnode.Type = unixfs.TFile
	fsnode.Data = filedata
	fsnodeData, err := fsnode.GetBytes()
	if err != nil {
		return "", "", err
	}
	// Wrap in inner DAG node
	innerDagnode := new(merkledag.Node)
	innerDagnode.SetData(fsnodeData)
	plaintext, err := innerDagnode.Marshal()
	if err != nil {
		return "", "", err
	}
	// Pad
	paddedSize := 0
	for paddedSize < len(plaintext)+4 {
		paddedSize += 1024
	}
	padded := make([]byte, paddedSize)
	binary.BigEndian.PutUint32(padded, uint32(len(plaintext)))
	copy(padded[4:], plaintext)
	// Encrypt
	ciphertext, err := Encrypt(padded, key)
	if err != nil {
		return "", "", err
	}
	// Wrap in outer DAG node
	outerDagnode := new(merkledag.Node)
	outerDagnode.SetData(ciphertext)
	blockData, err := outerDagnode.Marshal()
	if err != nil {
		return "", "", err
	}
	// Store in IPFS
	sh := shell.NewShell("localhost:5001")
	hash, err := sh.BlockPut(blockData)
	if err != nil {
		return "", "", err
	}
	keyString := base58.Encode(key[:])
	return hash, keyString, nil
}

func GetCommand(hash string, keyString string) error {
	keySlice := base58.Decode(keyString)
	key := new([32]byte)
	copy(key[:], keySlice)
	// Read from IPFS
	sh := shell.NewShell("localhost:5001")
	blockData, err := sh.BlockGet(hash)
	if err != nil {
		return err
	}
	// Decode outer DAG node
	outerDagnode, err := merkledag.DecodeProtobuf(blockData)
	if err != nil {
		return err
	}
	ciphertext := outerDagnode.Data()
	// Decrypt
	padded, err := Decrypt(ciphertext, key)
	if err != nil {
		return err
	}
	// Remove padding
	size := binary.BigEndian.Uint32(padded)
	if size > uint32(len(padded)-4) {
		return errors.New("Invalid size")
	}
	plaintext := padded[4 : 4+int(size)]
	// Decode inner DAG node
	innerDagnode, err := merkledag.DecodeProtobuf(plaintext)
	if err != nil {
		return err
	}
	fsnodeData := innerDagnode.Data()
	// Decode unixfs node
	fsnode, err := unixfs.FSNodeFromBytes(fsnodeData)
	if err != nil {
		return err
	}
	if fsnode.Type != unixfs.TFile && fsnode.Type != unixfs.TRaw {
		return errors.New("Must be file or raw")
	}
	// Write to file
	return ioutil.WriteFile(hash, fsnode.Data, 0644)
}

func NewKey() (*[32]byte, error) {
	var key [32]byte
	_, err := rand.Read(key[:])
	if err != nil {
		return nil, err
	}
	return &key, nil
}

func Encrypt(plaintext []byte, key *[32]byte) ([]byte, error) {
	var nonce [24]byte
	_, err := rand.Read(nonce[:])
	if err != nil {
		return nil, err
	}
	ciphertext := secretbox.Seal(nonce[:], plaintext, &nonce, key)
	return ciphertext, nil
}

func Decrypt(ciphertext []byte, key *[32]byte) ([]byte, error) {
	if len(ciphertext) < 24+secretbox.Overhead {
		return nil, errors.New("Invalid ciphertext")
	}
	var nonce [24]byte
	copy(nonce[:], ciphertext[:24])
	plaintext, ok := secretbox.Open(nil, ciphertext[24:], &nonce, key)
	if !ok {
		return nil, errors.New("Decryption failed")
	}
	return plaintext, nil
}
