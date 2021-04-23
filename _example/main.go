package main

import (
	"context"
	"fmt"
	"time"

	"github.com/libdns/libdns"
	"github.com/tombish/mythicbeasts-provider"
)

func main() {
	ctx := context.TODO()

	zone := "example.com."

	provider := mythicbeasts.Provider{KeyID: "KEYID_GOES_HERE", Secret: "SECRET_GOES_HERE"}

	// Get Records Test
	records, err := provider.GetRecords(ctx, zone)
	if err != nil {
		fmt.Printf("ERROR: %s\n", err.Error())
	}

	recordsAdded, err := provider.AppendRecords(ctx, zone, []libdns.Record{
		{Type: "A", Name: "test1", Value: "1.2.3.4", TTL: time.Duration(123) * time.Second},
		{Type: "CNAME", Name: "test2", Value: "proxy.server.com.", TTL: time.Duration(666) * time.Second},
	})
	if err != nil {
		fmt.Printf("ERROR: %s\n", err.Error())
	}

	recordsSet, err := provider.SetRecords(ctx, zone, []libdns.Record{
		{Type: "A", Name: "test1", Value: "5.2.3.4", TTL: time.Duration(999) * time.Second},
		{Type: "CNAME", Name: "test2", Value: "testies.test.me", TTL: time.Duration(999) * time.Second},
		{Type: "CNAME", Name: "test3", Value: "testies.test.no"},
	})
	if err != nil {
		fmt.Printf("ERROR: %s\n", err.Error())
	}

	recordsDeleted, err := provider.DeleteRecords(ctx, zone, []libdns.Record{
		{Type: "A", Name: "test1"},
		{Type: "CNAME", Name: "test2"},
	})
	if err != nil {
		fmt.Printf("ERROR: %s\n", err.Error())
	}

	fmt.Printf("\nThe following records are available from %s:\n%+v\n", zone, records)
	fmt.Printf("\nThe following records have been added to %s:\n%+v\n", zone, recordsAdded)
	fmt.Printf("\nThe following records have been set on %s:\n%+v\n", zone, recordsSet)
	fmt.Printf("\nThe following records have been deleted on %s:\n%s\n", zone, recordsDeleted)
}
