package main

import (
	"context"
	"fmt"
	"github.com/libdns/libdns"
	"os"
	"time"

	"github.com/tombish/mythicbeasts-provider"
)

func main() {
	_ = os.Setenv("LIBDNS_MYTHICBEASTS_KEYID", "PLACE_KEYID_HERE")
	_ = os.Setenv("LIBDNS_MYTHICBEASTS_SECRET", "PLACE_SECRET_HERE")
	_ = os.Setenv("LIBDNS_MYTHICBEASTS_ZONE", "PLACE_ZONE_HERE")

	keyID := os.Getenv("LIBDNS_MYTHICBEASTS_KEYID")
	secret := os.Getenv("LIBDNS_MYTHICBEASTS_SECRET")
	zone := os.Getenv("LIBDNS_MYTHICBEASTS_ZONE")

	p := &mythicbeasts.Provider{
		KeyID: keyID, Secret: secret,
	}
	// Get Records Test
	records, err := p.GetRecords(context.TODO(), zone)
	if err != nil {
		fmt.Printf("Error: %s", err.Error())
	}

	recordsToAdd := []libdns.Record{
		{Type: "A", Name: "test1", Value: "1.2.3.4", TTL: time.Duration(123) * time.Second},
		{Type: "CNAME", Name: "test2", Value: "proxy.server.com.", TTL: time.Duration(666) * time.Second},
	}

	recordsToSet := []libdns.Record{
		{Type: "A", Name: "test1", Value: "5.2.3.4", TTL: time.Duration(999) * time.Second},
		{Type: "CNAME", Name: "test2", Value: "testies.test.me", TTL: time.Duration(999) * time.Second},
		{Type: "CNAME", Name: "test3", Value: "testies.test.no"},
	}

	recordsToDelete := []libdns.Record{
		{Type: "A", Name: "test1"},
		{Type: "CNAME", Name: "test2"},
	}

	recordsAdded, err := p.AppendRecords(context.TODO(), zone, recordsToAdd)
	if err != nil {
		fmt.Printf("ERROR: %s\n", err.Error())
	}

	recordsSet, err := p.SetRecords(context.TODO(), zone, recordsToSet)
	if err != nil {
		fmt.Printf("ERROR: %s\n", err.Error())
	}

	recordsDeleted, err := p.DeleteRecords(context.TODO(), zone, recordsToDelete)
	if err != nil {
		fmt.Printf("ERROR: %s\n", err.Error())
	}

	fmt.Printf("\nThe following records are available from %s:\n%+v\n", zone, records)
	fmt.Printf("\nThe following records have been added to %s:\n%+v\n", zone, recordsAdded)
	fmt.Printf("\nThe following records have been set on %s:\n%+v\n", zone, recordsSet)
	fmt.Printf("\nThe following records have been deleted on %s:\n%s\n", zone, recordsDeleted)
}
