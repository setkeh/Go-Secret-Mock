package main

import (
	"context"
	"log"
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
)

// setupTestDbus sets up a test D-Bus environment with a service and client connection.
// It returns the service, client connections, and a cleanup function.
func setupTestDbus(t *testing.T) (*dbus.Conn, *dbus.Conn, func()) {
	// Use in-process D-Bus setup for testing
	serviceConn, err := dbus.ConnectSessionBus(nil)
	if err != nil {
		t.Fatalf("Failed to connect service to session bus: %v", err)
	}

	clientConn, err := dbus.ConnectSessionBus(nil)
	if err != nil {
		serviceConn.Close()
		t.Fatalf("Failed to connect client to session bus: %v", err)
	}

	cleanup := func() {
		serviceConn.Close()
		clientConn.Close()
	}

	return serviceConn, clientConn, cleanup
}

func TestDbusOpenSession(t *testing.T) {
	serviceConn, clientConn, cleanup := setupTestDbus(t)
	defer cleanup()

	// Create and export our SecretService
	secretService := &SecretService{
		Store:          NewInMemoryStore(),
		SessionsCrypto: make(map[dbus.ObjectPath]*SessionCrypto),
	}

	// Request the well-known name
	reply, err := serviceConn.RequestName(serviceName, dbus.NameFlagReplaceExisting)
	if err != nil {
		t.Fatalf("Service: Failed to request name %s: %v", serviceName, err)
	}
	if reply != dbus.RequestNameReplyPrimaryOwner {
		t.Fatalf("Service: Name %s already taken or other error: %v", serviceName, reply)
	}

	err = serviceConn.Export(secretService, objectPath, serviceInterface)
	if err != nil {
		t.Fatalf("Service: Failed to export SecretService object: %v", err)
	}

	// Client calls OpenSession
	obj := clientConn.Object(serviceName, objectPath)
	var sessionPath dbus.ObjectPath
	var serverPublicKey []byte

	// Simulate a client calling OpenSession with a dummy public key
	// In a real scenario, the client would generate its own DH key pair
	clientDummyPublicKey := []byte{0x01, 0x02, 0x03, 0x04} // Replace with actual client public key if needed for full DH handshake simulation

	call := obj.CallWithContext(context.Background(), serviceInterface+".OpenSession", 0, "dh-ietf1024-sha256-aes128-cbc-pkcs7", clientDummyPublicKey)
	if call.Err != nil {
		t.Fatalf("Client: Failed to call OpenSession: %v", call.Err)
	}

	err = call.Store(&sessionPath, &serverPublicKey)
	if err != nil {
		t.Fatalf("Client: Failed to store OpenSession results: %v", err)
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

// Helper function to introspect the service and print it (useful for debugging)
func introspectService(conn *dbus.Conn, serviceName string, objectPath dbus.ObjectPath) {
	node, err := introspect.NewIntrospectable(conn.Object(serviceName, objectPath)).Introspect()
	if err != nil {
		log.Printf("Failed to introspect %s: %v", objectPath, err)
		return
	}
	log.Printf("Introspection for %s:\n%s", objectPath, node.String())
}
