package main

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/libdns/libdns"
	"github.com/libdns/mythicbeasts"
)

func main() {
	keyID := os.Getenv("MYTHIC_KEY_ID")
	secret := os.Getenv("MYTHIC_SECRET")
	zone := os.Getenv("MYTHIC_ZONE")

	if keyID == "" || secret == "" {
		fmt.Println("Please set MYTHIC_KEY_ID and MYTHIC_SECRET environment variables.")
		return
	}

	// Allow overriding zone for testing
	if zone == "" {
		fmt.Println("Please set MYTHIC_ZONE environment variable.")
		return
	}

	ctx := context.TODO()

	provider := mythicbeasts.Provider{KeyID: keyID, Secret: secret}

	fmt.Printf("Listing records for zone: %s\n", zone)
	// Get Records Test
	records, err := provider.GetRecords(ctx, zone)
	if err != nil {
		fmt.Printf("ERROR: %s\n", err.Error())
	} else {
		fmt.Printf("GetRecords: Found %d records.\n", len(records))
	}

	// Append Records Test
	fmt.Println("\n--- Appending Records ---")
	recordsAdded, err := provider.AppendRecords(ctx, zone, []libdns.Record{
		libdns.Address{Name: "appendtest1", IP: netip.MustParseAddr("8.8.4.4"), TTL: time.Duration(123) * time.Second},
		libdns.Address{Name: "appendtest2", IP: netip.MustParseAddr("2a00:1098:0:80:1000:3b:1:1"), TTL: time.Duration(123) * time.Second},
		libdns.RR{Name: "appendtest3", Type: "ANAME", Data: "www.google.co.uk.", TTL: time.Duration(999) * time.Second},
		libdns.CNAME{Name: "appendtest4", Target: "www.example.com.", TTL: time.Duration(666) * time.Second},
		libdns.RR{Name: "appendtest5", Type: "DNAME", Data: "www.google.co.uk.", TTL: time.Duration(999) * time.Second},
		libdns.NS{Name: "appendtest6", Target: "ns1.mythic-beasts.com.", TTL: time.Duration(999) * time.Second},
		libdns.RR{Name: "appendtest7", Type: "PTR", Data: "test.example.com.", TTL: time.Duration(999) * time.Second},
		libdns.TXT{Name: "appendtest8", Text: "This is a test record", TTL: time.Duration(999) * time.Second},
		libdns.MX{Name: "appendtest9", Target: "mail.example.com.", Preference: 10, TTL: time.Duration(999) * time.Second},
		libdns.MX{Name: "appendtest10", Target: "mail2.example.com.", Preference: 20, TTL: time.Duration(999) * time.Second},
		libdns.CAA{Name: "appendtest11", Flags: 128, Tag: "issue", Value: "letsencrypt.org", TTL: time.Duration(999) * time.Second},
		libdns.SRV{Service: "sip", Transport: "tcp", Name: "appendtest12", Target: "srv.example.com.", Port: 443, Priority: 10, Weight: 5, TTL: time.Duration(999) * time.Second},
		libdns.RR{Name: "appendtest13", Type: "SSHFP", Data: "3 2 abc1234abc", TTL: time.Duration(999) * time.Second},
		libdns.RR{Name: "appendtest14", Type: "TLSA", Data: "2 1 2 dab111caba", TTL: time.Duration(999) * time.Second},
	})
	if err != nil {
		fmt.Printf("ERROR: %s\n", err.Error())
	}
	fmt.Printf("Added: %+v\n", recordsAdded)

	// Set Records Test - Demonstrating multiple records for same name (Fix verification)
	fmt.Println("\n--- Setting Records (Batch Update) ---")
	recordsSet, err := provider.SetRecords(ctx, zone, []libdns.Record{
		libdns.Address{Name: "settest1", IP: netip.MustParseAddr("8.8.8.8"), TTL: time.Duration(999) * time.Second},
		libdns.CNAME{Name: "settest2", Target: "test2.example.com", TTL: time.Duration(999) * time.Second},
		libdns.CNAME{Name: "settest3", Target: "test3.example.net"},
		libdns.MX{Name: "settest4", Target: "mail3.example.com.", Preference: 5, TTL: time.Duration(999) * time.Second},
		libdns.MX{Name: "settest5", Target: "mail4.example.com.", Preference: 8, TTL: time.Duration(999) * time.Second},
	})
	if err != nil {
		fmt.Printf("ERROR: %s\n", err.Error())
	}
	fmt.Printf("Set: %+v\n", recordsSet)

	// Delete Records Test
	fmt.Println("\n--- Deleting Records ---")
	recordsDeleted, err := provider.DeleteRecords(ctx, zone, []libdns.Record{
		libdns.Address{Name: "settest1"},
		libdns.CNAME{Name: "settest2"},
		libdns.RR{Type: "TXT", Name: "appendtest"},
		libdns.RR{Type: "A", Name: "multitest"},
	})
	if err != nil {
		fmt.Printf("ERROR: %s\n", err.Error())
	}

	fmt.Printf("\nThe following records are available from %s:\n%+v\n", zone, records)
	fmt.Printf("\nThe following records have been added to %s:\n%+v\n", zone, recordsAdded)
	fmt.Printf("\nThe following records have been set on %s:\n%+v\n", zone, recordsSet)
	fmt.Printf("\nThe following records have been deleted on %s:\n%s\n", zone, recordsDeleted)
}
