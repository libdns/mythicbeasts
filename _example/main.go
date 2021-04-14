package main

import (
	"context"
	"fmt"
	"github.com/tombish/mythicbeasts-provider"
	"os"
)

func main() {
	keyID := os.Getenv("LIBDNS_MYTHICBEASTS_TOKEN")
	if keyID == "" {
		fmt.Printf("LIBDNS_MYTHICBEASTS_TOKEN not set\n")
		return
	}

	secret := os.Getenv("LIBDNS_MYTHICBEASTS_SECRET")
	if secret == "" {
		fmt.Printf("LIBDNS_MYTHICBEASTS_SECRET not set\n")
		return
	}

	zone := os.Getenv("LIBDNS_MYTHICBEASTS_ZONE")
	if zone == "" {
		fmt.Printf("LIBDNS_MYTHICBEASTS_ZONE not set\n")
		return
	}

	p := &mythicbeasts.Provider{
		KeyID: keyID, Secret: secret,
	}

	records, err := p.GetRecords(context.TODO(), zone)
	if err != nil {
		fmt.Printf("Error: %s", err.Error())
		return
	}

	fmt.Println(records)
}
