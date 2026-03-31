package main

import (
	"crypto/aes"
	"fmt"
	"log"
	"math/big"
	"os"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
)

const (
	serviceName         = "org.freedesktop.secrets"
	objectPath          = "/org/freedesktop/secrets"
	collectionInterface = "org.freedesktop.Secret.Collection"
	serviceInterface    = "org.freedesktop.Secret.Service"
	propertiesInterface = "org.freedesktop.DBus.Properties"
	loginCollectionPath = "/org/freedesktop/secrets/collection/login"
)

// newDBusError creates a D-Bus error.
func newDBusError(name string, msg string) *dbus.Error {
	return dbus.MakeFailedError(dbus.NewError(name, []any{msg}))
}

// SessionCrypto holds cryptographic parameters for a session.
type SessionCrypto struct {
	PrivateKey   *big.Int
	SharedSecret []byte
	SessionKey   []byte
}

// SecretService implements all the necessary D-Bus interfaces.
type SecretService struct {
	Store          *InMemoryStore
	SessionsCrypto map[dbus.ObjectPath]*SessionCrypto
	mu             sync.Mutex
}

// DBusSecret is the D-Bus representation of a secret.
type DBusSecret struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

// --- org.freedesktop.Secret.Service Methods ---

func (s *SecretService) OpenSession(algorithm string, input dbus.Variant) (dbus.Variant, dbus.ObjectPath, *dbus.Error) {
	log.Println(">>> Service.OpenSession CALLED")
	defer log.Println("<<< Service.OpenSession RETURNED")

	if algorithm != "dh-ietf1024-sha256-aes128-cbc-pkcs7" {
		return dbus.MakeVariant(""), "", newDBusError("org.freedesktop.Secret.Error.UnsupportedAlgorithm", "Unsupported algorithm")
	}
	clientPublicKeyBytes, ok := input.Value().([]byte)
	if !ok {
		return dbus.MakeVariant(""), "", newDBusError("org.freedesktop.DBus.Error.InvalidArgs", "Input variant must be a byte array")
	}
	serverPrivateKey, serverPublicKey, err := GenerateDHKeyPair()
	if err != nil {
		return dbus.MakeVariant(""), "", newDBusError("org.freedesktop.Secret.Error.Failed", "Failed to generate DH key pair")
	}
	var sharedSecret *big.Int
	if len(clientPublicKeyBytes) > 0 {
		clientPublicKey := new(big.Int).SetBytes(clientPublicKeyBytes)
		sharedSecret, err = ComputeDHSharedSecret(serverPrivateKey, clientPublicKey)
		if err != nil {
			return dbus.MakeVariant(""), "", newDBusError("org.freedesktop.Secret.Error.Failed", "Failed to compute shared secret")
		}
	} else {
		sharedSecret = big.NewInt(0)
	}
	sessionKey := DeriveKeyFromSharedSecret(sharedSecret)
	s.mu.Lock()
	sessionPath := dbus.ObjectPath(fmt.Sprintf("/org/freedesktop/secrets/session/%d", s.Store.NextSessionID))
	s.Store.NextSessionID++
	s.mu.Unlock()
	s.SessionsCrypto[sessionPath] = &SessionCrypto{
		PrivateKey:   serverPrivateKey,
		SharedSecret: sharedSecret.Bytes(),
		SessionKey:   sessionKey,
	}
	s.Store.Sessions.Store(sessionPath, &Session{Path: sessionPath, Algorithm: algorithm, CreationTime: time.Now()})
	return dbus.MakeVariant(serverPublicKey.Bytes()), sessionPath, nil
}

func (s *SecretService) Unlock(objects []dbus.ObjectPath) ([]dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	log.Println(">>> Service.Unlock CALLED")
	defer log.Println("<<< Service.Unlock RETURNED")
	return objects, "/", nil
}

// --- org.freedesktop.Secret.Collection Methods (now on SecretService) ---

func (s *SecretService) SearchItems(attributes map[string]string) ([]dbus.ObjectPath, *dbus.Error) {
	log.Println(">>> Collection.SearchItems CALLED")
	defer log.Println("<<< Collection.SearchItems RETURNED")
	collectionVal, _ := s.Store.Collections.Load(loginCollectionPath)
	collection := collectionVal.(*Collection)
	var matchingItems []dbus.ObjectPath
	collection.Secrets.Range(func(key, value interface{}) bool {
		secret := value.(*Secret)
		match := true
		for attrKey, attrVal := range attributes {
			if secret.Attributes[attrKey] != attrVal {
				match = false
				break
			}
		}
		if match {
			matchingItems = append(matchingItems, secret.Path)
		}
		return true
	})
	return matchingItems, nil
}

func (s *SecretService) CreateItem(properties map[string]dbus.Variant, secret DBusSecret, replace bool) (dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	log.Println(">>> Collection.CreateItem CALLED")
	defer log.Println("<<< Collection.CreateItem RETURNED")

	collectionVal, _ := s.Store.Collections.Load(loginCollectionPath)
	collection := collectionVal.(*Collection)

	attributes := make(map[string]string)
	for k, v := range properties {
		if str, ok := v.Value().(string); ok {
			attributes[k] = str
		}
	}

	sessionCryptoVal, ok := s.SessionsCrypto[secret.Session]
	if !ok {
		return "", "", newDBusError("org.freedesktop.Secret.Error.NoSession", "Session not found")
	}

	iv, err := GenerateRandomBytes(aes.BlockSize)
	if err != nil {
		return "", "", newDBusError("org.freedesktop.Secret.Error.Failed", "IV generation failed")
	}
	encryptedValue, err := AESEncrypt(sessionCryptoVal.SessionKey, iv, secret.Value)
	if err != nil {
		return "", "", newDBusError("org.freedesktop.Secret.Error.Failed", "Encryption failed")
	}

	s.mu.Lock()
	newSecretID := s.Store.NextSecretID
	s.Store.NextSecretID++
	s.mu.Unlock()

	newSecretPath := dbus.ObjectPath(fmt.Sprintf("%s/item%d", loginCollectionPath, newSecretID))
	newSecret := &Secret{
		Path:        newSecretPath,
		Attributes:  attributes,
		ContentType: secret.ContentType,
		Value:       append(iv, encryptedValue...),
		Created:     time.Now(),
		Modified:    time.Now(),
		SessionPath: secret.Session,
	}
	collection.Secrets.Store(newSecretPath, newSecret)
	return newSecretPath, "/", nil
}

func (s *SecretService) GetSecrets(items []dbus.ObjectPath) (map[dbus.ObjectPath]DBusSecret, *dbus.Error) {
	log.Println(">>> Collection.GetSecrets CALLED")
	defer log.Println("<<< Collection.GetSecrets RETURNED")

	secrets := make(map[dbus.ObjectPath]DBusSecret)
	if len(items) == 0 {
		return secrets, nil
	}

	collectionVal, _ := s.Store.Collections.Load(loginCollectionPath)
	collection := collectionVal.(*Collection)
	
	// This is a big assumption: all secrets in a single GetSecrets call were encrypted with the same session.
	// We find the first secret and use its session for all of them.
	var sessionCrypto *SessionCrypto
	var sessionPath dbus.ObjectPath

	firstSecretVal, ok := collection.Secrets.Load(items[0])
	if !ok {
		return nil, newDBusError("org.freedesktop.Secret.Error.NoSuchObject", "First item not found")
	}
	firstSecret := firstSecretVal.(*Secret)
	sessionPath = firstSecret.SessionPath
	sessionCrypto, ok = s.SessionsCrypto[sessionPath]
	if !ok {
		return nil, newDBusError("org.freedesktop.Secret.Error.NoSession", "Session for decryption not found")
	}

	for _, itemPath := range items {
		secretVal, ok := collection.Secrets.Load(itemPath)
		if !ok { continue }
		internalSecret := secretVal.(*Secret)
		if len(internalSecret.Value) < aes.BlockSize { continue }
		iv := internalSecret.Value[:aes.BlockSize]
		encryptedValue := internalSecret.Value[aes.BlockSize:]
		decryptedValue, err := AESDecrypt(sessionCrypto.SessionKey, iv, encryptedValue)
		if err != nil { continue }
		secrets[itemPath] = DBusSecret{
			Session:     sessionPath,
			Parameters:  iv,
			Value:       decryptedValue,
			ContentType: internalSecret.ContentType,
		}
	}
	return secrets, nil
}


// --- org.freedesktop.DBus.Properties Methods ---

func (s *SecretService) Get(iface string, prop string) (dbus.Variant, *dbus.Error) {
	log.Printf(">>> Properties.Get CALLED for iface '%s', prop '%s'", iface, prop)
	defer log.Printf("<<< Properties.Get RETURNED for iface '%s', prop '%s'", iface, prop)
	
	if iface != collectionInterface {
		return dbus.MakeVariant(""), newDBusError("org.freedesktop.DBus.Error.InvalidArgs", "Invalid interface for Get")
	}
	collectionVal, _ := s.Store.Collections.Load(loginCollectionPath)
	collection := collectionVal.(*Collection)
	switch prop {
	case "Label":
		return dbus.MakeVariant(collection.Label), nil
	case "Locked":
		return dbus.MakeVariant(collection.Locked), nil
	case "Created":
		return dbus.MakeVariant(uint64(collection.Created.UnixMilli())), nil
	case "Modified":
		return dbus.MakeVariant(uint64(collection.Modified.UnixMilli())), nil
	case "Items":
		var items []dbus.ObjectPath
		collection.Secrets.Range(func(key, value interface{}) bool {
			items = append(items, key.(dbus.ObjectPath))
			return true
		})
		return dbus.MakeVariant(items), nil
	default:
		return dbus.MakeVariant(""), newDBusError("org.freedesktop.DBus.Error.InvalidArgs", "No such property")
	}
}

func (s *SecretService) GetAll(iface string) (map[string]dbus.Variant, *dbus.Error) {
	log.Printf(">>> Properties.GetAll CALLED for iface '%s'", iface)
	defer log.Printf("<<< Properties.GetAll RETURNED for iface '%s'", iface)

	if iface != collectionInterface {
		return nil, newDBusError("org.freedesktop.DBus.Error.InvalidArgs", "Invalid interface for GetAll")
	}
	collectionVal, _ := s.Store.Collections.Load(loginCollectionPath)
	collection := collectionVal.(*Collection)
	properties := make(map[string]dbus.Variant)
	properties["Label"] = dbus.MakeVariant(collection.Label)
	properties["Locked"] = dbus.MakeVariant(collection.Locked)
	var items []dbus.ObjectPath
	collection.Secrets.Range(func(key, value interface{}) bool {
		items = append(items, key.(dbus.ObjectPath))
		return true
	})
	properties["Items"] = dbus.MakeVariant(items)
	return properties, nil
}

func (s *SecretService) Set(iface string, prop string, value dbus.Variant) *dbus.Error {
	log.Printf(">>> Properties.Set CALLED for iface '%s', prop '%s'", iface, prop)
	defer log.Printf("<<< Properties.Set RETURNED for iface '%s', prop '%s'", iface, prop)

	if iface != collectionInterface {
		return newDBusError("org.freedesktop.DBus.Error.InvalidArgs", "Invalid interface for Set")
	}
	if prop == "Label" {
		if label, ok := value.Value().(string); ok {
			collectionVal, _ := s.Store.Collections.Load(loginCollectionPath)
			collection := collectionVal.(*Collection)
			collection.Label = label
			collection.Modified = time.Now()
			return nil
		}
		return newDBusError("org.freedesktop.DBus.Error.InvalidArgs", "Label must be a string")
	}
	return newDBusError("org.freedesktop.DBus.Error.PropertyReadOnly", "Property is read-only")
}

func main() {
	fmt.Println("Go Secret Mock Service starting...")
	addr := os.Getenv("DBUS_SESSION_BUS_ADDRESS")
	if addr == "" {
		log.Fatalln("FATAL: DBUS_SESSION_BUS_ADDRESS not set")
	}

	conn, err := dbus.Dial(addr)
	if err != nil {
		log.Fatalf("FATAL: Failed to connect to D-Bus at %s: %v\n", addr, err)
	}
	defer conn.Close()

	reply, err := conn.RequestName(serviceName, dbus.NameFlagReplaceExisting)
	if err != nil {
		log.Fatalf("FATAL: Failed to request name %s: %v", serviceName, err)
	}
	if reply != dbus.RequestNameReplyPrimaryOwner {
		log.Fatalf("FATAL: Name %s already taken: %v", serviceName, reply)
	}

	secretService := &SecretService{
		Store:          NewInMemoryStore(),
		SessionsCrypto: make(map[dbus.ObjectPath]*SessionCrypto),
	}

	// Export the single service object on the main service path for the Service interface
	err = conn.Export(secretService, objectPath, serviceInterface)
	if err != nil {
		log.Fatalf("FATAL: Failed to export Secret.Service interface: %v", err)
	}
	
	// Also export the same object on the collection path for Collection and Properties interfaces
	err = conn.Export(secretService, loginCollectionPath, collectionInterface)
	if err != nil {
		log.Fatalf("FATAL: Failed to export Secret.Collection interface: %v", err)
	}
	err = conn.Export(secretService, loginCollectionPath, propertiesInterface)
	if err != nil {
		log.Fatalf("FATAL: Failed to export DBus.Properties interface on collection path: %v", err)
	}

	fmt.Println("Service started. Listening for D-Bus calls...")
	select {}
}
