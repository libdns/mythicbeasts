package mythicbeasts

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
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
	// TODO: put config fields here (with snake_case json
	// struct tags on exported fields), for example:
	KeyID  string `json:"key_id,omitempty"`
	Secret string `json:"secret,omitempty"`
	token  mythicAuthResponse
}

// GetRecords lists all records in given zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	err := p.login()
	if err != nil {
		fmt.Errorf("login: provider login failed: %d", err)
		return nil, err
	}

	req, err := http.NewRequest("GET", apiURL+"/zones/"+zone+"/records", nil)
	if err != nil {
		fmt.Errorf("login: provider record request failed: %d", err)
		return nil, err
	}
	req.Header.Set("Authorization", os.ExpandEnv("Bearer "+p.token.Token))

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

	result := mythicRecordsResponse{}
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
	return nil, fmt.Errorf("TODO: not implemented")
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// It returns the updated records.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	return nil, fmt.Errorf("TODO: not implemented")
}

// DeleteRecords deletes the records from the zone. It returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	return nil, fmt.Errorf("TODO: not implemented")
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
