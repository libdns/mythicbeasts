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
		return nil, fmt.Errorf("login: provider login failed: %w", err)
	}

	formatedZone, err := publicsuffix.EffectiveTLDPlusOne(p.unFQDN(zone))
	if err != nil {
		return nil, fmt.Errorf("Provided zone string malformed: %w", err)
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
		return nil, fmt.Errorf("GetRecords: failed to unmarshal response: %w", err)
	}

	var records []libdns.Record

	for _, r := range result.Records {
		record, err := r.GetLibdnsRecord()
		if err != nil {
			return nil, fmt.Errorf("GetRecords: failed to parse record %s: %w", r.GetName(), err)
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
		return nil, fmt.Errorf("login: provider login failed: %w", err)
	}

	formatedZone, err := publicsuffix.EffectiveTLDPlusOne(p.unFQDN(zone))
	if err != nil {
		return nil, fmt.Errorf("Provided zone string malformed: %w", err)
	}

	// Batch add records
	appendedRecords, err := p.addRecords(ctx, formatedZone, zone, records)
	if err != nil {
		return nil, fmt.Errorf("AppendRecords: %w", err)
	}

	return appendedRecords, nil
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// It returns the updated records.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	err := p.login(ctx)
	if err != nil {
		return nil, fmt.Errorf("login: provider login failed: %w", err)
	}

	formatedZone, err := publicsuffix.EffectiveTLDPlusOne(p.unFQDN(zone))
	if err != nil {
		return nil, fmt.Errorf("Provided zone string malformed: %w", err)
	}

	// Atomic set records
	setRecord, err := p.setRecordsAtomic(ctx, formatedZone, zone, records)
	if err != nil {
		return nil, fmt.Errorf("SetRecords: %w", err)
	}
	return setRecord, nil
}

// DeleteRecords deletes the records from the zone. It returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	err := p.login(ctx)
	if err != nil {
		return nil, fmt.Errorf("login: provider login failed: %w", err)
	}

	formatedZone, err := publicsuffix.EffectiveTLDPlusOne(p.unFQDN(zone))
	if err != nil {
		return nil, fmt.Errorf("Provided zone string malformed: %w", err)
	}

	var deletedRecords []libdns.Record

	for _, record := range records {
		deletedRecord, err := p.removeRecord(ctx, formatedZone, zone, record)
		if err != nil {
			return deletedRecords, fmt.Errorf("DeleteRecords: %w", err)
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

// fqdnOf returns the FQDN of the recordName relative to the zone.
func fqdnOf(recordName, zone string) string {
	cleanRec := strings.TrimSuffix(strings.TrimSpace(recordName), ".")
	cleanZone := strings.TrimSuffix(strings.TrimSpace(zone), ".")
	if cleanRec == "" || cleanRec == "@" {
		return cleanZone
	}
	return cleanRec + "." + cleanZone
}

// relativeName returns the name of fqdn relative to zone, and true if fqdn is within zone.
// If fqdn is not within zone, it returns "", false.
func relativeName(fqdn, zone string) (string, bool) {
	cleanFQDN := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(fqdn)), ".")
	cleanZone := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zone)), ".")

	if cleanFQDN == cleanZone {
		return "", true
	}

	suffix := "." + cleanZone
	if strings.HasSuffix(cleanFQDN, suffix) {
		// Use original case of the prefix of fqdn
		fqdnNoDot := strings.TrimSuffix(fqdn, ".")
		relLen := len(fqdnNoDot) - len(suffix)
		if relLen >= 0 {
			return fqdnNoDot[:relLen], true
		}
	}

	return "", false
}

// adjustRecordName copies the record with its name adjusted relative to formatedZone.
func (p *Provider) adjustRecordName(originalZone, formatedZone string, record libdns.Record) libdns.Record {
	fqdn := fqdnOf(record.RR().Name, originalZone)
	relName, ok := relativeName(fqdn, formatedZone)
	if !ok {
		// Fallback to original record name just in case
		return record
	}

	name := relName
	if srv, ok := record.(libdns.SRV); ok {
		prefix := "_" + srv.Service + "._" + srv.Transport
		if strings.HasPrefix(relName, prefix+".") {
			name = relName[len(prefix)+1:]
		} else if relName == prefix {
			name = ""
		}
	}

	switch r := record.(type) {
	case libdns.Address: r.Name = name; return r
	case libdns.CNAME:   r.Name = name; return r
	case libdns.NS:      r.Name = name; return r
	case libdns.TXT:     r.Name = name; return r
	case libdns.RR:      r.Name = name; return r
	case libdns.MX:      r.Name = name; return r
	case libdns.CAA:     r.Name = name; return r
	case libdns.SRV:     r.Name = name; return r
	default:
		return record
	}
}

