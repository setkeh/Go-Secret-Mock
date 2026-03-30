package main

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"math/big"
	"testing"
)

func TestGenerateDHKeyPair(t *testing.T) {
	privateKey, publicKey, err := GenerateDHKeyPair()
	if err != nil {
		t.Fatalf("GenerateDHKeyPair failed: %v", err)
	}

	if privateKey.Cmp(big.NewInt(0)) <= 0 {
		t.Errorf("Private key should be greater than 0")
	}
	if privateKey.Cmp(dhP) >= 0 {
		t.Errorf("Private key should be less than P")
	}
	if publicKey.Cmp(big.NewInt(0)) <= 0 {
		t.Errorf("Public key should be greater than 0")
	}
	if publicKey.Cmp(dhP) >= 0 {
		t.Errorf("Public key should be less than P")
	}
}

func TestComputeDHSharedSecret(t *testing.T) {
	// Alice's keys
	alicePrivateKey, alicePublicKey, err := GenerateDHKeyPair()
	if err != nil {
		t.Fatalf("Alice GenerateDHKeyPair failed: %v", err)
	}

	// Bob's keys
	bobPrivateKey, bobPublicKey, err := GenerateDHKeyPair()
	if err != nil {
		t.Fatalf("Bob GenerateDHKeyPair failed: %v", err)
	}

	// Alice computes shared secret
	aliceSharedSecret, err := ComputeDHSharedSecret(alicePrivateKey, bobPublicKey)
	if err != nil {
		t.Fatalf("Alice ComputeDHSharedSecret failed: %v", err)
	}

	// Bob computes shared secret
	bobSharedSecret, err := ComputeDHSharedSecret(bobPrivateKey, alicePublicKey)
	if err != nil {
		t.Fatalf("Bob ComputeDHSharedSecret failed: %v", err)
	}

	if aliceSharedSecret.Cmp(bobSharedSecret) != 0 {
		t.Errorf("Shared secrets do not match: Alice's %s, Bob's %s", aliceSharedSecret.String(), bobSharedSecret.String())
	}
}

func TestDeriveKeyFromSharedSecret(t *testing.T) {
	sharedSecret := big.NewInt(12345)
	key := DeriveKeyFromSharedSecret(sharedSecret)

	if len(key) != 32 { // SHA256 produces 32 bytes
		t.Errorf("Derived key length is %d, expected 32", len(key))
	}

	// Corrected expected hash for SHA256 of big.NewInt(12345).Bytes() which is []byte{0x30, 0x39}
	expectedHash := []byte{
		0x35, 0x14, 0xac, 0xf6, 0x17, 0x32, 0xf6, 0x62, 0xda, 0x19, 0x62, 0x5f, 0x7f, 0xe7, 0x81, 0xc3,
		0xe4, 0x83, 0xf2, 0xdc, 0xe8, 0x50, 0x60, 0x12, 0xf3, 0xbb, 0x39, 0x3f, 0x50, 0x03, 0xe1, 0x05,
	}
	if !bytes.Equal(key, expectedHash) {
		t.Errorf("Derived key does not match expected hash.\nGot:      %x\nExpected: %x", key, expectedHash)
	}
}

func TestAESEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32) // AES-256 key
	_, err := rand.Read(key)
	if err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	iv := make([]byte, aes.BlockSize) // AES block size is 16 bytes
	_, err = rand.Read(iv)
	if err != nil {
		t.Fatalf("Failed to generate random IV: %v", err)
	}

	plaintext := []byte("This is a test message that needs to be encrypted and decrypted.")

	ciphertext, err := AESEncrypt(key, iv, plaintext)
	if err != nil {
		t.Fatalf("AESEncrypt failed: %v", err)
	}

	decryptedText, err := AESDecrypt(key, iv, ciphertext)
	if err != nil {
		t.Fatalf("AESDecrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decryptedText) {
		t.Errorf("Decrypted text does not match original plaintext.\nOriginal: %s\nDecrypted: %s", plaintext, decryptedText)
	}

	// Test with different plaintext lengths
	shortPlaintext := []byte("short")
	shortCiphertext, err := AESEncrypt(key, iv, shortPlaintext)
	if err != nil {
		t.Fatalf("AESEncrypt short failed: %v", err)
	}
	shortDecrypted, err := AESDecrypt(key, iv, shortCiphertext)
	if err != nil {
		t.Fatalf("AESDecrypt short failed: %v", err)
	}
	if !bytes.Equal(shortPlaintext, shortDecrypted) {
		t.Errorf("Short decrypted text does not match original plaintext.")
	}

	// Test with plaintext that is a multiple of block size
	blockPlaintext := bytes.Repeat([]byte("a"), aes.BlockSize)
	blockCiphertext, err := AESEncrypt(key, iv, blockPlaintext)
	if err != nil {
		t.Fatalf("AESEncrypt block failed: %v", err)
	}
	blockDecrypted, err := AESDecrypt(key, iv, blockCiphertext)
	if err != nil {
		t.Fatalf("AESDecrypt block failed: %v", err)
	}
	if !bytes.Equal(blockPlaintext, blockDecrypted) {
		t.Errorf("Block decrypted text does not match original plaintext.")
	}
}

func TestPKCS7Padding(t *testing.T) {
	// Test cases for pkcs7Pad and pkcs7Unpad
	testCases := []struct {
		name      string
		plaintext []byte
		blockSize int
	}{
		{"Empty plaintext", []byte{}, aes.BlockSize},
		{"Multiple of block size", bytes.Repeat([]byte("a"), aes.BlockSize), aes.BlockSize},
		{"Less than block size", []byte("short"), aes.BlockSize},
		{"More than block size", []byte("this is a longer message"), aes.BlockSize},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			padded := pkcs7Pad(tc.plaintext, tc.blockSize)
			if len(padded)%tc.blockSize != 0 {
				t.Errorf("Padded length %d not a multiple of block size %d", len(padded), tc.blockSize)
			}
			unpadded, err := pkcs7Unpad(padded, tc.blockSize)
			if err != nil {
				t.Fatalf("pkcs7Unpad failed: %v", err)
			}
			if !bytes.Equal(tc.plaintext, unpadded) {
				t.Errorf("Unpadded text does not match original plaintext.\nOriginal: %x\nUnpadded: %x", tc.plaintext, unpadded)
			}
		})
	}

	t.Run("Invalid padding", func(t *testing.T) {
		// Create a deliberately invalid padding: last byte indicates padding of 4, but the byte before it is not 4.
		invalidPadded := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x04}
		_, err := pkcs7Unpad(invalidPadded, aes.BlockSize)
		if err == nil {
			t.Error("pkcs7Unpad should have returned an error for invalid padding")
		}
	})
	t.Run("Empty input", func(t *testing.T) {
		_, err := pkcs7Unpad([]byte{}, aes.BlockSize)
		if err == nil {
			t.Error("pkcs7Unpad should have returned an error for empty input")
		}
	})
	t.Run("Padding value larger than length", func(t *testing.T) {
		_, err := pkcs7Unpad([]byte{0x10}, aes.BlockSize)
		if err == nil {
			t.Error("pkcs7Unpad should have returned an error for padding value larger than length")
		}
	})
	t.Run("Padding value larger than block size", func(t *testing.T) {
		invalidPadded := bytes.Repeat([]byte("a"), aes.BlockSize*2)
		invalidPadded[len(invalidPadded)-1] = byte(aes.BlockSize + 1)
		_, err := pkcs7Unpad(invalidPadded, aes.BlockSize)
		if err == nil {
			t.Error("pkcs7Unpad should have returned an error for padding value larger than block size")
		}
	})
}
