package mythicbeasts

import (
	"context"
	"fmt"
	"net/url"
	"strings"
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

// unFQDN trims any trailing "." from fqdn.
func (p *Provider) unFQDN(fqdn string) string {
	return strings.TrimSuffix(fqdn, ".")
}

// GetRecords lists all records in given zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	err := p.login(ctx)
	if err != nil {
		return nil, fmt.Errorf("login: provider login failed: %d", err)
	}

	formatedZone, err := publicsuffix.EffectiveTLDPlusOne(p.unFQDN(zone))
	if err != nil {
		return nil, fmt.Errorf("Provided zone string malformed %d", err)
	}

	p.mutex.Lock()
	defer p.mutex.Unlock()

	respBody, err := p.doAPIRequest(ctx, "GET", apiURL+"/zones/"+url.PathEscape(formatedZone)+"/records", nil)
	if err != nil {
		return nil, fmt.Errorf("GetRecords: %w", err)
	}

	result := mythicRecords{}

	err = result.UnmarshalJSON(respBody)
	if err != nil {
		return nil, fmt.Errorf("GetRecords: failed to unmarshal response: %d", err)
	}

	var records []libdns.Record

	for _, r := range result.Records {
		record, err := r.GetLibdnsRecord()
		if err != nil {
			return nil, fmt.Errorf("GetRecords: failed to parse record %s: %d", r.GetName(), err)
		}

		records = append(records, record)
	}
	return records, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	err := p.login(ctx)
	if err != nil {
		return nil, fmt.Errorf("login: provider login failed: %d", err)
	}

	formatedZone, err := publicsuffix.EffectiveTLDPlusOne(p.unFQDN(zone))
	if err != nil {
		return nil, fmt.Errorf("Provided zone string malformed %d", err)
	}

	// Batch add records
	appendedRecords, err := p.addRecords(ctx, formatedZone, records)
	if err != nil {
		return nil, fmt.Errorf("AppendRecords: %d", err)
	}

	return appendedRecords, nil
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// It returns the updated records.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	err := p.login(ctx)
	if err != nil {
		return nil, fmt.Errorf("login: provider login failed: %d", err)
	}

	formatedZone, err := publicsuffix.EffectiveTLDPlusOne(p.unFQDN(zone))
	if err != nil {
		return nil, fmt.Errorf("Provided zone string malformed %d", err)
	}

	// Atomic set records
	setRecord, err := p.setRecordsAtomic(ctx, formatedZone, records)
	if err != nil {
		return nil, fmt.Errorf("SetRecords: %d", err)
	}
	return setRecord, nil
}

// DeleteRecords deletes the records from the zone. It returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	err := p.login(ctx)
	if err != nil {
		return nil, fmt.Errorf("login: provider login failed: %d", err)
	}

	formatedZone, err := publicsuffix.EffectiveTLDPlusOne(p.unFQDN(zone))
	if err != nil {
		return nil, fmt.Errorf("Provided zone string malformed %d", err)
	}

	var deletedRecords []libdns.Record

	for _, record := range records {
		deletedRecord, err := p.removeRecord(ctx, formatedZone, record)
		if err != nil {
			return deletedRecords, fmt.Errorf("DeleteRecords: %d", err)
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
