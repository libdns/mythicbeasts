package main

import (
	"context"
	"fmt"
	"github.com/libdns/libdns"
	"os"
	"time"

	//TODO: revise on submission to libdns
	"github.com/tombish/mythicbeasts-provider"
)

func main() {
	keyID := os.Getenv("LIBDNS_MYTHICBEASTS_KEYID")
	if keyID == "" {
		fmt.Printf("LIBDNS_MYTHICBEASTS_KEYID not set\n")
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
	// Get Records Test
	records, err := p.GetRecords(context.TODO(), zone)
	if err != nil {
		fmt.Printf("Error: %s", err.Error())
		return
	}

	fmt.Printf("The following records are available from %s:\n", zone)
	fmt.Println(records)

	// Append Records Test
	recordsToAdd := []libdns.Record{
		{Type: "A", Name: "test1", Value: "1.2.3.4", TTL: time.Duration(123) * time.Second},
		{Type: "CNAME", Name: "test2", Value: "proxy.server.com.", TTL: time.Duration(666) * time.Second},
	}

	recordsAdded, err := p.AppendRecords(context.TODO(), zone, recordsToAdd)
	if err != nil {
		fmt.Printf("ERROR: %s\n", err.Error())
	}

	fmt.Printf("The following records have been added to %s:\n", zone)
	fmt.Println(recordsAdded)
}
