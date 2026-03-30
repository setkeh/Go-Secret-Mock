package main

import (
	"fmt"
	"github.com/godbus/dbus/v5"
)

func main() {
	fmt.Println("Attempting to connect to D-Bus...")
	conn, err := dbus.ConnectSession(nil)
	if err != nil {
		fmt.Printf("Failed to connect to session bus: %v\n", err)
		return
	}
	defer conn.Close()
	fmt.Println("Successfully connected to D-Bus session bus.")
}

