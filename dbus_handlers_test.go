package main

import (
	"bytes" // Added import
	"sync"  // Added import
	"testing"

	"github.com/godbus/dbus/v5"
)

func TestDbusOpenSession(t *testing.T) {
	// Create and export our SecretService
	secretService := &SecretService{
		Store:          NewInMemoryStore(),
		SessionsCrypto: make(map[dbus.ObjectPath]*SessionCrypto),
	}

	// Simulate a client calling OpenSession with a dummy public key
	clientDummyPublicKey := []byte{0x01, 0x02, 0x03, 0x04}

	// Directly call the OpenSession method
	outputVariant, sessionPath, err := secretService.OpenSession("dh-ietf1024-sha256-aes128-cbc-pkcs7", dbus.MakeVariant(clientDummyPublicKey))
	if err != nil {
		t.Fatalf("OpenSession failed: %v", err)
	}

	serverPublicKey, ok := outputVariant.Value().([]byte)
	if !ok {
		t.Fatalf("Server public key is not a byte array")
	}

	if sessionPath == "" || sessionPath == "/" {
		t.Errorf("Expected a valid session path, got %s", sessionPath)
	}
	if len(serverPublicKey) == 0 {
		t.Errorf("Expected a non-empty server public key")
	}

	// Verify that a new session and its crypto parameters are stored
	sessionVal, ok := secretService.Store.Sessions.Load(sessionPath)
	if !ok {
		t.Errorf("Session with path %s not found in store", sessionPath)
	} else {
		session := sessionVal.(*Session)
		if session.Path != sessionPath {
			t.Errorf("Stored session path mismatch: got %s, expected %s", session.Path, sessionPath)
		}
		if session.Algorithm != "dh-ietf1024-sha256-aes128-cbc-pkcs7" {
			t.Errorf("Stored session algorithm mismatch: got %s, expected %s", session.Algorithm, "dh-ietf1024-sha256-aes128-cbc-pkcs7")
		}
	}

	cryptoVal, ok := secretService.SessionsCrypto[sessionPath]
	if !ok {
		t.Errorf("Session crypto for path %s not found", sessionPath)
	} else {
		if cryptoVal.PrivateKey == nil || cryptoVal.SessionKey == nil {
			t.Errorf("Session crypto missing private key or session key")
		}
	}
}

func TestDbusUnlock(t *testing.T) {
	secretService := &SecretService{
		Store:          NewInMemoryStore(),
		SessionsCrypto: make(map[dbus.ObjectPath]*SessionCrypto),
	}

	testObjects := []dbus.ObjectPath{"/org/freedesktop/secrets/collection/login/item/1", "/org/freedesktop/secrets/collection/login/item/2"}

	unlocked, prompt, err := secretService.Unlock(testObjects)
	if err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}

	if !compareObjectPaths(unlocked, testObjects) {
		t.Errorf("Unlocked objects mismatch. Got %v, expected %v", unlocked, testObjects)
	}
	if prompt != "/" {
		t.Errorf("Prompt mismatch. Got %s, expected /", prompt)
	}
}

func TestDbusCreateItem(t *testing.T) {
	secretService := &SecretService{
		Store:          NewInMemoryStore(),
		SessionsCrypto: make(map[dbus.ObjectPath]*SessionCrypto),
	}

	// First, establish a session for encryption
	_, sessionPath, err := secretService.OpenSession("dh-ietf1024-sha256-aes128-cbc-pkcs7", dbus.MakeVariant([]byte{}))
	if err != nil {
		t.Fatalf("Failed to open session: %v", err)
	}

	collectionVal, _ := secretService.Store.Collections.LoadOrStore("/org/freedesktop/secrets/collection/login", &Collection{Secrets: &sync.Map{}})
	collectionObj := &CollectionObject{
		Path:          "/org/freedesktop/secrets/collection/login",
		Collection:    collectionVal.(*Collection),
		SecretService: secretService,
	}

	properties := map[string]dbus.Variant{
		"attr1": dbus.MakeVariant("value1"),
		"attr2": dbus.MakeVariant("value2"),
	}
	dbusSecret := DBusSecret{
		Session:     sessionPath,
		Value:       []byte("mysecretpassword"),
		ContentType: "text/plain",
	}

	newSecretPath, prompt, err := collectionObj.CreateItem(properties, dbusSecret, false)
	if err != nil {
		t.Fatalf("CreateItem failed: %v", err)
	}

	if newSecretPath == "" || newSecretPath == "/" {
		t.Errorf("Expected a valid new secret path, got %s", newSecretPath)
	}
	if prompt != "/" {
		t.Errorf("Prompt mismatch. Got %s, expected /", prompt)
	}

	// Verify the item is stored in the collection
	storedSecretVal, ok := collectionObj.Collection.Secrets.Load(newSecretPath)
	if !ok {
		t.Errorf("Created secret not found in store at path: %s", newSecretPath)
	}
	storedSecret := storedSecretVal.(*Secret)

	if storedSecret.ContentType != dbusSecret.ContentType {
		t.Errorf("Stored secret ContentType mismatch. Got %s, expected %s", storedSecret.ContentType, dbusSecret.ContentType)
	}
	if storedSecret.SessionPath != sessionPath {
		t.Errorf("Stored secret SessionPath mismatch. Got %s, expected %s", storedSecret.SessionPath, sessionPath)
	}

	// Try to retrieve the secret and decrypt it
	secretsMap, err := collectionObj.GetSecrets([]dbus.ObjectPath{newSecretPath})
	if err != nil {
		t.Fatalf("GetSecrets failed: %v", err)
	}
	retrievedDBusSecret, ok := secretsMap[newSecretPath]
	if !ok {
		t.Errorf("Retrieved secret not found in secrets map")
	}

	if !bytes.Equal(retrievedDBusSecret.Value, dbusSecret.Value) {
		t.Errorf("Decrypted secret value mismatch.\nGot:      %s\nExpected: %s", retrievedDBusSecret.Value, dbusSecret.Value)
	}
}

func TestDbusGetSecrets(t *testing.T) {
	secretService := &SecretService{
		Store:          NewInMemoryStore(),
		SessionsCrypto: make(map[dbus.ObjectPath]*SessionCrypto),
	}

	// 1. Establish a session
	_, sessionPath, err := secretService.OpenSession("dh-ietf1024-sha256-aes128-cbc-pkcs7", dbus.MakeVariant([]byte{}))
	if err != nil {
		t.Fatalf("Failed to open session: %v", err)
	}

	// 2. Prepare a collection object
	collectionVal, _ := secretService.Store.Collections.LoadOrStore("/org/freedesktop/secrets/collection/login", &Collection{Secrets: &sync.Map{}})
	collectionObj := &CollectionObject{
		Path:          "/org/freedesktop/secrets/collection/login",
		Collection:    collectionVal.(*Collection),
		SecretService: secretService,
	}

	// 3. Create a secret item
	plaintextSecret := []byte("another_secret_password")
	properties := map[string]dbus.Variant{
		"service": dbus.MakeVariant("test-service"),
		"user":    dbus.MakeVariant("test-user"),
	}
	dbusSecret := DBusSecret{
		Session:     sessionPath,
		Value:       plaintextSecret,
		ContentType: "text/plain",
	}

	createdSecretPath, _, err := collectionObj.CreateItem(properties, dbusSecret, false)
	if err != nil {
		t.Fatalf("CreateItem failed: %v", err)
	}

	// 4. Retrieve the secret using GetSecrets
	retrievedSecretsMap, err := collectionObj.GetSecrets([]dbus.ObjectPath{createdSecretPath})
	if err != nil {
		t.Fatalf("GetSecrets failed: %v", err)
	}

	retrievedDBusSecret, ok := retrievedSecretsMap[createdSecretPath]
	if !ok {
		t.Fatalf("Secret not found in retrieved secrets map for path: %s", createdSecretPath)
	}

	// 5. Assert the decrypted value matches the original plaintext
	if !bytes.Equal(retrievedDBusSecret.Value, plaintextSecret) {
		t.Errorf("Decrypted secret value mismatch.\nGot:      %s\nExpected: %s", retrievedDBusSecret.Value, plaintextSecret)
	}
	if retrievedDBusSecret.Session != dbus.ObjectPath(sessionPath) {
		t.Errorf("Retrieved secret session path mismatch. Got %s, expected %s", retrievedDBusSecret.Session, sessionPath)
	}
	if retrievedDBusSecret.ContentType != dbusSecret.ContentType {
		t.Errorf("Retrieved secret content type mismatch. Got %s, expected %s", retrievedDBusSecret.ContentType, dbusSecret.ContentType)
	}

	// Test getting a non-existent secret (should just return empty map for that item)
	nonExistentPath := dbus.ObjectPath("/non/existent/secret")
	retrievedEmptyMap, err := collectionObj.GetSecrets([]dbus.ObjectPath{nonExistentPath})
	if err != nil {
		t.Fatalf("GetSecrets failed for non-existent secret: %v", err)
	}
	if _, ok := retrievedEmptyMap[nonExistentPath]; ok {
		t.Errorf("Retrieved a non-existent secret")
	}
}

// Helper to compare two slices of dbus.ObjectPath
func compareObjectPaths(a, b []dbus.ObjectPath) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
