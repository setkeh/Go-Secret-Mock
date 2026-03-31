package main

import (
	"fmt"
	"log"
	"math/big"
	"os"
	"sync"
	"time"

	"crypto/aes" // Added import

	"github.com/godbus/dbus/v5"
)

const (
	serviceName      = "org.freedesktop.secrets"
	objectPath       = "/org/freedesktop/secrets"
	serviceInterface = "org.freedesktop.Secret.Service"
)

// newDBusError is a helper function to create *dbus.Error
func newDBusError(name string, msg string) *dbus.Error {
	return dbus.MakeFailedError(dbus.NewError(name, []any{msg}))
}

// SessionCrypto holds cryptographic parameters for a specific session
type SessionCrypto struct {
	PrivateKey   *big.Int
	SharedSecret []byte
	SessionKey   []byte // Derived from SharedSecret
}

// SecretService represents our D-Bus service
type SecretService struct {
	Store          *InMemoryStore
	SessionsCrypto map[dbus.ObjectPath]*SessionCrypto // Stores crypto info per session
	mu             sync.Mutex                         // Mutex to protect SessionsCrypto
}

// DBusSecret represents the D-Bus Secret structure.
type DBusSecret struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

// CollectionObject represents a D-Bus collection object
type CollectionObject struct {
	Path          dbus.ObjectPath
	Collection    *Collection    // Reference to the actual in-memory collection
	SecretService *SecretService // A reference back to the main service
}

// Get implements the org.freedesktop.DBus.Properties.Get method for a collection.
func (c *CollectionObject) Get(iface, prop string) (dbus.Variant, *dbus.Error) {
	log.Printf("CollectionObject.Get called for interface %s, property %s on path %s", iface, prop, c.Path)

	if iface == "org.freedesktop.Secret.Collection" {
		switch prop {
		case "Locked":
			return dbus.MakeVariant(c.Collection.Locked), nil
		case "Label":
			return dbus.MakeVariant(c.Collection.Label), nil
		case "Created":
			// D-Bus expects Unix timestamps in milliseconds
			return dbus.MakeVariant(uint64(c.Collection.Created.UnixMilli())), nil
		case "Modified":
			return dbus.MakeVariant(uint64(c.Collection.Modified.UnixMilli())), nil
		case "Items":
			var items []dbus.ObjectPath
			c.Collection.Secrets.Range(func(key, value interface{}) bool {
				items = append(items, key.(dbus.ObjectPath))
				return true
			})
			return dbus.MakeVariant(items), nil
		case "Attributes": // Attributes for a collection, typically empty or specific metadata
			return dbus.MakeVariant(map[string]string{}), nil
		}
	} else if iface == "org.freedesktop.DBus.Properties" {
		switch prop {
		case "Interfaces": // List of interfaces implemented by this object
			return dbus.MakeVariant([]string{"org.freedesktop.Secret.Collection", "org.freedesktop.DBus.Properties"}), nil
		}
	}

	return dbus.MakeVariant(nil), newDBusError("org.freedesktop.DBus.Error.InvalidArgs", fmt.Sprintf("No such property %s on interface %s", prop, iface))
}

// GetAll implements the org.freedesktop.DBus.Properties.GetAll method for a collection.
func (c *CollectionObject) GetAll(iface string) (map[string]dbus.Variant, *dbus.Error) {
	log.Printf("CollectionObject.GetAll called for interface %s on path %s", iface, c.Path)
	properties := make(map[string]dbus.Variant)

	if iface == "org.freedesktop.Secret.Collection" {
		properties["Locked"] = dbus.MakeVariant(c.Collection.Locked)
		properties["Label"] = dbus.MakeVariant(c.Collection.Label)
		properties["Created"] = dbus.MakeVariant(uint64(c.Collection.Created.UnixMilli()))
		properties["Modified"] = dbus.MakeVariant(uint64(c.Collection.Modified.UnixMilli()))
		var items []dbus.ObjectPath
		c.Collection.Secrets.Range(func(key, value interface{}) bool {
			items = append(items, key.(dbus.ObjectPath))
			return true
		})
		properties["Items"] = dbus.MakeVariant(items)
		properties["Attributes"] = dbus.MakeVariant(map[string]string{})
	} else if iface == "org.freedesktop.DBus.Properties" {
		properties["Interfaces"] = dbus.MakeVariant([]string{"org.freedesktop.Secret.Collection", "org.freedesktop.DBus.Properties"})
	}

	return properties, nil
}

// Set implements the org.freedesktop.DBus.Properties.Set method for a collection.
func (c *CollectionObject) Set(iface, prop string, value dbus.Variant) *dbus.Error {
	log.Printf("CollectionObject.Set called for interface %s, property %s, value %v on path %s", iface, prop, value, c.Path)

	if iface == "org.freedesktop.Secret.Collection" {
		switch prop {
		case "Label":
			if label, ok := value.Value().(string); ok {
				c.Collection.Label = label
				c.Collection.Modified = time.Now()
				return nil
			}
			return newDBusError("org.freedesktop.DBus.Error.InvalidArgs", "Label must be a string")
		case "Locked":
			// In our mock, collections are never truly locked, so we ignore attempts to lock/unlock.
			return nil
		default:
			return newDBusError("org.freedesktop.DBus.Error.InvalidArgs", fmt.Sprintf("Cannot set property %s on interface %s", prop, iface))
		}
	}
	return newDBusError("org.freedesktop.DBus.Error.InvalidArgs", fmt.Sprintf("Cannot set property %s on interface %s", prop, iface))
}

// Delete deletes the collection. For now, it's a no-op that always returns success.
func (c *CollectionObject) Delete() (dbus.ObjectPath, *dbus.Error) {
	log.Printf("Delete called for collection: %s", c.Path)
	// For mock, just return success and no prompt
	return "/", nil
}

// SearchItems searches for secret items in the collection based on provided attributes.
func (c *CollectionObject) SearchItems(attributes map[string]string) ([]dbus.ObjectPath, *dbus.Error) {
	log.Printf("SearchItems called for collection %s with attributes: %v", c.Path, attributes)
	var matchingItems []dbus.ObjectPath

	c.Collection.Secrets.Range(func(key, value interface{}) bool {
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

// CreateItem creates a new secret item in the collection.
func (c *CollectionObject) CreateItem(properties map[string]dbus.Variant, secret DBusSecret, replace bool) (dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	log.Printf("CreateItem called for collection %s, properties: %v, secret: %v, replace: %t", c.Path, properties, secret, replace)

	// Extract attributes from properties
	attributes := make(map[string]string)
	for k, v := range properties {
		if s, ok := v.Value().(string); ok {
			attributes[k] = s
		}
	}

	// Check for existing secret if replace is true
	if replace {
		existingItems, err := c.SearchItems(attributes)
		if err != nil {
			return "", "", newDBusError("org.freedesktop.Secret.Error.Failed", fmt.Sprintf("Failed to search for existing items: %v", err))
		}
		if len(existingItems) > 0 {
			// For simplicity, just replace the first one found
			existingSecretVal, ok := c.Collection.Secrets.Load(existingItems[0])
			if ok {
				existingSecret := existingSecretVal.(*Secret)
				existingSecret.Value = secret.Value // Update value
				existingSecret.Modified = time.Now()
				log.Printf("Replaced existing secret at path: %s", existingSecret.Path)
				return existingSecret.Path, "/", nil
			}
		}
	}

	// Retrieve session key
	sessionCryptoVal, ok := c.SecretService.SessionsCrypto[secret.Session]
	if !ok {
		log.Printf("Session crypto not found for session path: %s", secret.Session)
		return "", "", newDBusError("org.freedesktop.Secret.Error.NoSession", "Session not found or expired")
	}
	sessionKey := sessionCryptoVal.SessionKey

	// Generate IV
	iv, err := GenerateRandomBytes(aes.BlockSize)
	if err != nil {
		log.Printf("Failed to generate IV: %v", err)
		return "", "", newDBusError("org.freedesktop.Secret.Error.Failed", "Failed to generate IV")
	}

	// Encrypt the secret value
	encryptedValue, err := AESEncrypt(sessionKey, iv, secret.Value)
	if err != nil {
		log.Printf("Failed to encrypt secret value: %v", err)
		return "", "", newDBusError("org.freedesktop.Secret.Error.Failed", "Failed to encrypt secret value")
	}

	// Prepend IV to the encrypted value
	finalSecretValue := append(iv, encryptedValue...)

	// Generate new secret path
	c.SecretService.mu.Lock()
	newSecretPath := dbus.ObjectPath(fmt.Sprintf("%s/item/%d", c.Path, c.SecretService.Store.NextSecretID))
	c.SecretService.Store.NextSecretID++
	c.SecretService.mu.Unlock()

	newSecret := &Secret{
		Path:        newSecretPath,
		Attributes:  attributes,
		ContentType: secret.ContentType,
		Value:       finalSecretValue,
		Created:     time.Now(),
		Modified:    time.Now(),
		SessionPath: secret.Session, // Store the session path used for encryption
	}

	c.Collection.Secrets.Store(newSecretPath, newSecret)
	log.Printf("Created new secret at path: %s", newSecretPath)

	return newSecretPath, "/", nil
}

// GetSecrets retrieves the actual secret values for the given items.
func (c *CollectionObject) GetSecrets(itemPaths []dbus.ObjectPath) (map[dbus.ObjectPath]DBusSecret, *dbus.Error) {
	log.Printf("GetSecrets called for collection %s with items: %v", c.Path, itemPaths)
	secrets := make(map[dbus.ObjectPath]DBusSecret)

	for _, itemPath := range itemPaths {
		secretVal, ok := c.Collection.Secrets.Load(itemPath)
		if !ok {
			log.Printf("Secret not found at path: %s", itemPath)
			continue
		}
		internalSecret := secretVal.(*Secret)

		// Retrieve session crypto using the SessionPath stored in the internal secret
		sessionCryptoVal, ok := c.SecretService.SessionsCrypto[internalSecret.SessionPath]
		if !ok {
			log.Printf("Session crypto not found for session path: %s for secret %s", internalSecret.SessionPath, itemPath)
			continue
		}
		sessionKey := sessionCryptoVal.SessionKey

		// The IV is prepended to the encrypted value
		if len(internalSecret.Value) < aes.BlockSize {
			log.Printf("Secret value too short for decryption (path: %s)", itemPath)
			continue
		}
		iv := internalSecret.Value[:aes.BlockSize]
		encryptedValue := internalSecret.Value[aes.BlockSize:]

		decryptedValue, err := AESDecrypt(sessionKey, iv, encryptedValue)
		if err != nil {
			log.Printf("Failed to decrypt secret at path %s: %v", itemPath, err)
			continue
		}

		secrets[itemPath] = DBusSecret{
			Session:     internalSecret.SessionPath, // Now correctly linked
			Parameters:  []byte{},                   // Parameters from original DBusSecret - currently not stored in internal secret
			Value:       decryptedValue,
			ContentType: internalSecret.ContentType,
		}
	}
	return secrets, nil
}

// OpenSession handles the D-Bus OpenSession method call.
// It performs a Diffie-Hellman key exchange.
func (s *SecretService) OpenSession(algorithm string, input dbus.Variant) (dbus.Variant, dbus.ObjectPath, *dbus.Error) {
	log.Printf("OpenSession called with algorithm: %s", algorithm)

	if algorithm != "dh-ietf1024-sha256-aes128-cbc-pkcs7" {
		log.Printf("Unsupported algorithm: %s", algorithm)
		return dbus.MakeVariant(""), "", newDBusError("org.freedesktop.Secret.Error.UnsupportedAlgorithm", "Unsupported algorithm")
	}

	clientPublicKeyBytes, ok := input.Value().([]byte)
	if !ok {
		return dbus.MakeVariant(""), "", newDBusError("org.freedesktop.DBus.Error.InvalidArgs", "Input variant is not a byte array")
	}

	// Generate server's DH key pair
	serverPrivateKey, serverPublicKey, err := GenerateDHKeyPair()
	if err != nil {
		log.Printf("Failed to generate DH key pair: %v", err)
		return dbus.MakeVariant(""), "", newDBusError("org.freedesktop.Secret.Error.Failed", "Failed to generate DH key pair")
	}

	var sharedSecret *big.Int
	if len(clientPublicKeyBytes) > 0 {
		clientPublicKey := new(big.Int).SetBytes(clientPublicKeyBytes)
		sharedSecret, err = ComputeDHSharedSecret(serverPrivateKey, clientPublicKey)
		if err != nil {
			log.Printf("Failed to compute shared secret: %v", err)
			return dbus.MakeVariant(""), "", newDBusError("org.freedesktop.Secret.Error.Failed", "Failed to compute shared secret")
		}
	} else {
		log.Println("Client public key is empty. Proceeding with a dummy shared secret for now.")
		sharedSecret = big.NewInt(0) // Dummy shared secret
	}

	// Derive session key
	sessionKey := DeriveKeyFromSharedSecret(sharedSecret)

	// Create a new session in the store
	s.mu.Lock()
	sessionPath := dbus.ObjectPath(fmt.Sprintf("/org/freedesktop/secrets/session/%d", s.Store.NextSessionID))
	s.Store.NextSessionID++
	s.mu.Unlock()

	session := &Session{
		Path:         sessionPath,
		Algorithm:    algorithm,
		SharedSecret: sessionKey,
		CreationTime: time.Now(),
	}
	s.Store.Sessions.Store(sessionPath, session)

	// Store crypto parameters for this session
	s.mu.Lock()
	s.SessionsCrypto[sessionPath] = &SessionCrypto{
		PrivateKey:   serverPrivateKey,
		SharedSecret: sharedSecret.Bytes(),
		SessionKey:   sessionKey,
	}
	s.mu.Unlock()

	log.Printf("OpenSession successful. New session path: %s", sessionPath)
	return dbus.MakeVariant(serverPublicKey.Bytes()), sessionPath, nil
}

// Unlock automatically returns the requested object paths as unlocked and a null path for the prompt.
func (s *SecretService) Unlock(objects []dbus.ObjectPath) ([]dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	log.Printf("Unlock called for objects: %v", objects)
	// As per requirements, automatically return all objects as unlocked and no prompt
	return objects, "/", nil
}

func main() {
	fmt.Println("Go Secret Mock Service starting...")

	addr := os.Getenv("DBUS_SESSION_BUS_ADDRESS")
	if addr == "" {
		fmt.Fprintln(os.Stderr, "DBUS_SESSION_BUS_ADDRESS not set")
		os.Exit(1)
	}

	// Connect explicitly to the address
	conn, err := dbus.Dial(addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to connect to %s: %v\n", addr, err)
		os.Exit(1)
	}
	defer conn.Close()

	reply, err := conn.RequestName(serviceName, dbus.NameFlagReplaceExisting)
	if err != nil {
		log.Fatalf("Failed to request name %s: %v", serviceName, err)
	}
	if reply != dbus.RequestNameReplyPrimaryOwner {
		log.Fatalf("Name %s already taken or other error: %v", serviceName, reply)
	}

	secretService := &SecretService{
		Store:          NewInMemoryStore(),
		SessionsCrypto: make(map[dbus.ObjectPath]*SessionCrypto),
	}

	err = conn.Export(secretService, objectPath, serviceInterface)
	if err != nil {
		log.Fatalf("Failed to export object: %v", err)
	}

	// Export the default "login" collection
	loginCollectionPath := dbus.ObjectPath("/org/freedesktop/secrets/collection/login")
	iface := "org.freedesktop.Secret.Collection"
	ifaceProps := "org.freedesktop.DBus.Properties" // For getting/setting properties on the collection object

	collectionVal, ok := secretService.Store.Collections.Load(loginCollectionPath)
	if !ok {
		log.Fatalf("Login collection not found in store, this should not happen.")
	}
	loginCollection := collectionVal.(*Collection)

	loginCollectionObject := &CollectionObject{
		Path:          loginCollectionPath,
		Collection:    loginCollection,
		SecretService: secretService, // Pass the reference to the main service
	}

	err = conn.Export(loginCollectionObject, loginCollectionPath, iface)
	if err != nil {
		log.Fatalf("Failed to export login collection object for interface %s: %v", iface, err)
	}

	// Export standard D-Bus properties interface for the collection
	err = conn.Export(loginCollectionObject, loginCollectionPath, ifaceProps)
	if err != nil {
		log.Fatalf("Failed to export login collection object for interface %s: %v", ifaceProps, err)
	}

	fmt.Println("Service started. Listening for D-Bus calls...")

	select {} // Block forever to keep the service running
}
