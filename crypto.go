package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"
	"log"
)

// RFC 2409 Group 2 (1024-bit) parameters
// P = 2^1024 - 2^960 - 1 + 2^64 * ((2^894 * pi) + 793)
// This is a well-known prime for Diffie-Hellman Group 2
var (
	// Prime P (1024-bit)
	dhP, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431BFE9A48C0AD521B2DE51EED6F4557C34E78229F23E370C1AC1FD76EDCBBFFEB56EECEF447C4FEE356763402426A30ED9715A322", 16)
	// Generator G
	dhG = big.NewInt(2)
)

// GenerateDHKeyPair generates a Diffie-Hellman private and public key pair.
func GenerateDHKeyPair() (*big.Int, *big.Int, error) {
	// Private key x should be a random number between 1 and P-1
	privateKey, err := rand.Int(rand.Reader, new(big.Int).Sub(dhP, big.NewInt(1)))
	if err != nil {
		return nil, nil, err
	}

	// Public key Y = G^x mod P
	publicKey := new(big.Int).Exp(dhG, privateKey, dhP)

	return privateKey, publicKey, nil
}

// ComputeDHSharedSecret computes the shared secret K = Y_remote^x_local mod P.
func ComputeDHSharedSecret(privateKey *big.Int, remotePublicKey *big.Int) (*big.Int, error) {
	if privateKey == nil || remotePublicKey == nil {
		return nil, errors.New("private key or remote public key cannot be nil")
	}
	sharedSecret := new(big.Int).Exp(remotePublicKey, privateKey, dhP)
	return sharedSecret, nil
}

// DeriveKeyFromSharedSecret uses SHA256 to derive a 32-byte key from the shared secret.
func DeriveKeyFromSharedSecret(sharedSecret *big.Int) []byte {
	hash := sha256.Sum256(sharedSecret.Bytes())
	return hash[:]
}

// pkcs7Pad appends PKCS7 padding to the plaintext.
func pkcs7Pad(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := make([]byte, padding)
	for i := 0; i < padding; i++ {
		padtext[i] = byte(padding)
	}
	return append(ciphertext, padtext...)
}

// pkcs7Unpad removes PKCS7 padding from the plaintext.
func pkcs7Unpad(paddedText []byte, blockSize int) ([]byte, error) {
	textLen := len(paddedText)
	if textLen == 0 {
		return nil, errors.New("pkcs7 unpad error: empty input")
	}
	padding := int(paddedText[textLen-1])
	if padding == 0 || padding > blockSize || padding > textLen {
		return nil, errors.New("pkcs7 unpad error: invalid padding")
	}
	for i := 0; i < padding; i++ {
		if paddedText[textLen-1-i] != byte(padding) {
			return nil, errors.New("pkcs7 unpad error: invalid padding bytes")
		}
	}
	return paddedText[:textLen-padding], nil
}

// AESEncrypt encrypts plaintext using AES-128-CBC with the given key and IV.
func AESEncrypt(key, iv, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(iv) != aes.BlockSize {
		return nil, errors.New("AESEncrypt: IV length must be equal to block size")
	}

	paddedPlaintext := pkcs7Pad(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(paddedPlaintext))

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, paddedPlaintext)

	return ciphertext, nil
}

// AESDecrypt decrypts ciphertext using AES-128-CBC with the given key and IV.
func AESDecrypt(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(iv) != aes.BlockSize {
		return nil, errors.New("AESDecrypt: IV length must be equal to block size")
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("AESDecrypt: ciphertext is not a multiple of the block size")
	}

	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	return pkcs7Unpad(plaintext, aes.BlockSize)
}

// GenerateRandomBytes generates a slice of cryptographically secure random bytes of the specified length.
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		log.Printf("Error generating random bytes: %v", err)
		return nil, err
	}
	return b, nil
}
