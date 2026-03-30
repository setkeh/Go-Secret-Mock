package main

import (
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
)

// Session represents an active D-Bus session
type Session struct {
	Path        dbus.ObjectPath
	Algorithm   string
	SharedSecret []byte
	CreationTime time.Time
	// Add more session-specific data as needed
}

// Collection represents a secret collection
type Collection struct {
	Path        dbus.ObjectPath
	Label       string
	Created     time.Time
	Modified    time.Time
	Locked      bool
	Secrets     *sync.Map // map[dbus.ObjectPath]*Secret
}

// Secret represents a stored secret item
type Secret struct {
	Path        dbus.ObjectPath
	Attributes  map[string]string
	ContentType string
	Value       []byte
	Created     time.Time
	Modified    time.Time
	SessionPath dbus.ObjectPath // New field to store the session used for encryption
}

// InMemoryStore holds all the in-memory data for the secret service
type InMemoryStore struct {
	Sessions    *sync.Map // map[dbus.ObjectPath]*Session
	Collections *sync.Map // map[dbus.ObjectPath]*Collection
	NextSessionID int
	NextCollectionID int
	NextSecretID int
}

// NewInMemoryStore initializes and returns a new InMemoryStore
func NewInMemoryStore() *InMemoryStore {
	store := &InMemoryStore{
		Sessions:    &sync.Map{},
		Collections: &sync.Map{},
		NextSessionID: 1,
		NextCollectionID: 1,
		NextSecretID: 1,
	}

	// Emulate a default collection at /org/freedesktop/secrets/collection/login
	loginCollectionPath := dbus.ObjectPath("/org/freedesktop/secrets/collection/login")
	loginCollection := &Collection{
		Path:        loginCollectionPath,
		Label:       "Login",
		Created:     time.Now(),
		Modified:    time.Now(),
		Locked:      false,
		Secrets:     &sync.Map{},
	}
	store.Collections.Store(loginCollectionPath, loginCollection)

	return store
}

// Global store instance
var store = NewInMemoryStore()
