package main

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/libdns/libdns"
	"github.com/libdns/mythicbeasts"
)

func main() {
	keyID := os.Getenv("MYTHIC_KEY_ID")
	secret := os.Getenv("MYTHIC_SECRET")
	zone := os.Getenv("MYTHIC_ZONE")

	if keyID == "" || secret == "" || zone == "" {
		fmt.Println("Please set MYTHIC_KEY_ID, MYTHIC_SECRET, and MYTHIC_ZONE environment variables.")
		return
	}

	ctx := context.TODO()
	provider := mythicbeasts.Provider{KeyID: keyID, Secret: secret}

	// Prefix all test records to keep track of them easily
	const testPrefix = "libdnstest-"

	// Keep track of records we need to clean up at the end
	var recordsToClean []libdns.Record

	// Cleanup function to ensure DNS is left clean
	cleanup := func() {
		if len(recordsToClean) == 0 {
			return
		}
		fmt.Printf("\n--- Cleaning Up DNS (Deleting %d Test Records) ---\n", len(recordsToClean))
		
		type recordKey struct {
			name  string
			rType string
		}
		seen := make(map[recordKey]bool)
		var uniqueDeletes []libdns.Record
		for _, r := range recordsToClean {
			rr := r.RR()
			key := recordKey{name: rr.Name, rType: rr.Type}
			if !seen[key] {
				seen[key] = true
				uniqueDeletes = append(uniqueDeletes, r)
			}
		}

		deleted, err := provider.DeleteRecords(ctx, zone, uniqueDeletes)
		if err != nil {
			fmt.Printf("Cleanup Error: %v\n", err)
		} else {
			fmt.Printf("Successfully deleted %d records from the zone.\n", len(deleted))
		}
	}
	defer cleanup()

	fmt.Printf("Starting Mythic Beasts Integration Test for Zone: %s\n", zone)

	fmt.Println("\n--- Fetching Initial Records ---")
	initialRecords, err := provider.GetRecords(ctx, zone)
	if err != nil {
		fmt.Printf("Failed to get initial records: %v\n", err)
		return
	}
	fmt.Printf("Found %d existing records in the zone.\n", len(initialRecords))

	fmt.Println("\n--- Appending Test Records ---")
	recordsToAppend := []libdns.Record{
		libdns.Address{Name: testPrefix + "a", IP: netip.MustParseAddr("1.2.3.4"), TTL: 300 * time.Second},
		libdns.Address{Name: testPrefix + "aaaa", IP: netip.MustParseAddr("2001:db8::1"), TTL: 300 * time.Second},
		libdns.CNAME{Name: testPrefix + "cname", Target: "target.example.com.", TTL: 300 * time.Second},
		libdns.TXT{Name: testPrefix + "txt", Text: "Hello Mythic Beasts", TTL: 300 * time.Second},
		libdns.MX{Name: testPrefix + "mx", Target: "mail.example.com.", Preference: 10, TTL: 300 * time.Second},
		libdns.CAA{Name: testPrefix + "caa", Flags: 128, Tag: "issue", Value: "letsencrypt.org", TTL: 300 * time.Second},
		libdns.SRV{Service: "sip", Transport: "tcp", Name: testPrefix + "srv", Target: "srv.example.com.", Port: 5060, Priority: 10, Weight: 5, TTL: 300 * time.Second},
	}

	for _, r := range recordsToAppend {
		rr := r.RR()
		appended, err := provider.AppendRecords(ctx, zone, []libdns.Record{r})
		if err != nil {
			if strings.Contains(err.Error(), "403") || strings.Contains(err.Error(), "Access denied") {
				fmt.Printf("  [Skipped] %s (%s): Access Denied (Key restricted/read-only for this type)\n", rr.Name, rr.Type)
			} else {
				fmt.Printf("  [Failed] %s (%s): %v\n", rr.Name, rr.Type, err)
			}
			continue
		}
		for _, rec := range appended {
			recRR := rec.RR()
			fmt.Printf("  [Appended] %s (%s) -> %s\n", recRR.Name, recRR.Type, recRR.Data)
			recordsToClean = append(recordsToClean, rec)
		}
	}

	fmt.Println("\n--- Setting Records (Upsert / Update) ---")
	recordsToSet := []libdns.Record{
		// Update the previously added TXT record (always allowed if TXT is allowed)
		libdns.TXT{Name: testPrefix + "txt", Text: "Updated Hello Mythic Beasts", TTL: 600 * time.Second},
		// Try updating an A record (might be skipped if key is restricted)
		libdns.Address{Name: testPrefix + "a", IP: netip.MustParseAddr("5.6.7.8"), TTL: 600 * time.Second},
		// Try a new A record (might be skipped)
		libdns.Address{Name: testPrefix + "new-a", IP: netip.MustParseAddr("9.10.11.12"), TTL: 300 * time.Second},
	}

	for _, r := range recordsToSet {
		rr := r.RR()
		set, err := provider.SetRecords(ctx, zone, []libdns.Record{r})
		if err != nil {
			if strings.Contains(err.Error(), "403") || strings.Contains(err.Error(), "Access denied") {
				fmt.Printf("  [Skipped] %s (%s): Access Denied (Key restricted/read-only for this type)\n", rr.Name, rr.Type)
			} else {
				fmt.Printf("  [Failed] %s (%s): %v\n", rr.Name, rr.Type, err)
			}
			continue
		}
		for _, rec := range set {
			recRR := rec.RR()
			fmt.Printf("  [Set] %s (%s) -> %s\n", recRR.Name, recRR.Type, recRR.Data)
			recordsToClean = append(recordsToClean, rec)
		}
	}

	fmt.Println("\n--- Verifying Current Records ---")
	currentRecords, err := provider.GetRecords(ctx, zone)
	if err != nil {
		fmt.Printf("Failed to verify records: %v\n", err)
		return
	}

	fmt.Println("Created/Modified test records found in the zone:")
	foundCount := 0
	for _, r := range currentRecords {
		rr := r.RR()
		if strings.HasPrefix(rr.Name, testPrefix) || strings.HasPrefix(rr.Name, "_sip._tcp."+testPrefix) {
			fmt.Printf("  - %s (%s) -> %s [TTL: %s]\n", rr.Name, rr.Type, rr.Data, rr.TTL)
			foundCount++
		}
	}
	fmt.Printf("Total test records active: %d\n", foundCount)

	// Cleanup will run automatically via defer, leaving the DNS profile completely clean!
}
