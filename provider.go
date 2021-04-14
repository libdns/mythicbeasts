package mythicbeasts

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/libdns/libdns"
)

// TODO: Providers must not require additional provisioning steps by the callers; it
// should work simply by populating a struct and calling methods on it. If your DNS
// service requires long-lived state or some extra provisioning step, do it implicitly
// when methods are called; sync.Once can help with this, and/or you can use a
// sync.(RW)Mutex in your Provider struct to synchronize implicit provisioning.

// Provider facilitates DNS record manipulation with Mythic Beasts.
type Provider struct {
	KeyID  string `json:"key_id,omitempty"`
	Secret string `json:"secret,omitempty"`
	token  mythicAuthResponse

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
		fmt.Errorf("login: provider login failed: %d", err)
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL+"/zones/"+zone+"/records", nil)
	if err != nil {
		fmt.Errorf("login: provider record request failed: %d", err)
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+p.token.Token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Errorf("login: provider record request failed: %d", err)
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Errorf("login: failed to read response body: %d", err)
		return nil, err
	}

	result := mythicRecords{}
	if err := json.Unmarshal(body, &result); err != nil {
		fmt.Errorf("login: failed to extract JSON data: %d", err)
		return nil, err
	}
	var records []libdns.Record

	for _, r := range result.Records {
		records = append(records, libdns.Record{
			Type:  r.Type,
			Name:  r.Name,
			Value: r.Value,
			TTL:   time.Duration(r.TTL) * time.Second,
		})
	}
	return records, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	err := p.login(ctx)
	if err != nil {
		fmt.Errorf("login: provider login failed: %d", err)
		return nil, err
	}

	var appendedRecords []libdns.Record

	for _, record := range records {
		newRecord, err := p.addRecord(ctx, p.unFQDN(zone), record)
		if err != nil {
			fmt.Errorf("AppendRecords: %d", err)
			return nil, err
		}
		appendedRecords = append(appendedRecords, newRecord[0])
	}

	return appendedRecords, nil
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// It returns the updated records.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	err := p.login(ctx)
	if err != nil {
		fmt.Errorf("login: provider login failed: %d", err)
		return nil, err
	}

	var setRecords []libdns.Record

	for _, record := range records {
		setRecord, err := p.updateRecord(ctx, p.unFQDN(zone), record)
		if err != nil {
			fmt.Errorf("SetRecords: %d", err)
			return setRecords, err
		}
		setRecords = append(setRecords, setRecord...)
	}

	return setRecords, nil
}

// DeleteRecords deletes the records from the zone. It returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	err := p.login(ctx)
	if err != nil {
		fmt.Errorf("login: provider login failed: %d", err)
		return nil, err
	}

	var deletedRecords []libdns.Record

	for _, record := range records {
		deletedRecord, err := p.removeRecord(ctx, p.unFQDN(zone), record)
		if err != nil {
			fmt.Errorf("DeleteRecords: %d", err)
			return deletedRecords, err
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
