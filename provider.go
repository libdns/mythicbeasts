package mythicbeasts

import (
	"context"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/libdns/libdns"
	"golang.org/x/net/publicsuffix"
)

// Provider facilitates DNS record manipulation with Mythic Beasts.
type Provider struct {
	KeyID  string `json:"key_id,omitempty"`
	Secret string `json:"secret,omitempty"`

	token          mythicAuthResponse
	tokenExpiresAt time.Time

	mutex sync.Mutex
}

// GetRecords lists all records in given zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	err := p.login(ctx)
	if err != nil {
		return nil, fmt.Errorf("mythicbeasts: failed getting records for zone %s: %w", zone, err)
	}

	formatedZone, err := publicsuffix.EffectiveTLDPlusOne(p.unFQDN(zone))
	if err != nil {
		return nil, fmt.Errorf("mythicbeasts: failed getting records for zone %s: provided zone string malformed: %w", zone, err)
	}

	p.mutex.Lock()
	defer p.mutex.Unlock()

	respBody, err := p.doRequest(ctx, "GET", "/zones/"+url.PathEscape(formatedZone)+"/records", nil)
	if err != nil {
		return nil, fmt.Errorf("mythicbeasts: failed getting records for zone %s: %w", zone, err)
	}

	result := mythicRecords{}

	err = result.UnmarshalJSON(respBody)
	if err != nil {
		return nil, fmt.Errorf("mythicbeasts: failed getting records for zone %s: failed to unmarshal response: %w", zone, err)
	}

	var records []libdns.Record

	for _, r := range result.Records {
		record, err := r.GetLibdnsRecord()
		if err != nil {
			return nil, fmt.Errorf("mythicbeasts: failed getting records for zone %s: failed to parse record %s: %w", zone, r.GetName(), err)
		}

		fqdn := fqdnOf(record.RR().Name, formatedZone)
		_, ok := relativeName(fqdn, zone)
		if !ok {
			continue
		}

		adjusted := p.adjustRecordName(formatedZone, zone, record)
		records = append(records, adjusted)
	}
	return records, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	err := p.login(ctx)
	if err != nil {
		return nil, fmt.Errorf("mythicbeasts: failed appending records for zone %s: %w", zone, err)
	}

	formatedZone, err := publicsuffix.EffectiveTLDPlusOne(p.unFQDN(zone))
	if err != nil {
		return nil, fmt.Errorf("mythicbeasts: failed appending records for zone %s: provided zone string malformed: %w", zone, err)
	}

	// Batch add records
	appendedRecords, err := p.addRecords(ctx, formatedZone, zone, records)
	if err != nil {
		return nil, fmt.Errorf("mythicbeasts: failed appending records for zone %s: %w", zone, err)
	}

	return appendedRecords, nil
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// It returns the updated records.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	err := p.login(ctx)
	if err != nil {
		return nil, fmt.Errorf("mythicbeasts: failed setting records for zone %s: %w", zone, err)
	}

	formatedZone, err := publicsuffix.EffectiveTLDPlusOne(p.unFQDN(zone))
	if err != nil {
		return nil, fmt.Errorf("mythicbeasts: failed setting records for zone %s: provided zone string malformed: %w", zone, err)
	}

	// Atomic set records
	setRecord, err := p.setRecordsAtomic(ctx, formatedZone, zone, records)
	if err != nil {
		return nil, fmt.Errorf("mythicbeasts: failed setting records for zone %s: %w", zone, err)
	}
	return setRecord, nil
}

// DeleteRecords deletes the records from the zone. It returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	err := p.login(ctx)
	if err != nil {
		return nil, fmt.Errorf("mythicbeasts: failed deleting records for zone %s: %w", zone, err)
	}

	formatedZone, err := publicsuffix.EffectiveTLDPlusOne(p.unFQDN(zone))
	if err != nil {
		return nil, fmt.Errorf("mythicbeasts: failed deleting records for zone %s: provided zone string malformed: %w", zone, err)
	}

	var deletedRecords []libdns.Record

	for _, record := range records {
		deletedRecord, err := p.removeRecord(ctx, formatedZone, zone, record)
		if err != nil {
			return deletedRecords, fmt.Errorf("mythicbeasts: failed deleting records for zone %s: %w", zone, err)
		}
		deletedRecords = append(deletedRecords, deletedRecord...)
	}

	return deletedRecords, nil
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
