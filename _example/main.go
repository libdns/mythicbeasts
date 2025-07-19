package main

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/libdns/libdns"
	"github.com/libdns/mythicbeasts"
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

	// Append Records Test
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
	})
	if err != nil {
		fmt.Printf("ERROR: %s\n", err.Error())
	}

	// Set Records Test
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

	// Delete Records Test
	recordsDeleted, err := provider.DeleteRecords(ctx, zone, []libdns.Record{
		libdns.Address{Name: "settest1"},
		libdns.CNAME{Name: "settest2"},
	})
	if err != nil {
		fmt.Printf("ERROR: %s\n", err.Error())
	}

	fmt.Printf("\nThe following records are available from %s:\n%+v\n", zone, records)
	fmt.Printf("\nThe following records have been added to %s:\n%+v\n", zone, recordsAdded)
	fmt.Printf("\nThe following records have been set on %s:\n%+v\n", zone, recordsSet)
	fmt.Printf("\nThe following records have been deleted on %s:\n%s\n", zone, recordsDeleted)
}
