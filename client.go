package mythicbeasts

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/libdns/libdns"
)

var (
	apiURL  = "https://api.mythic-beasts.com/dns/v2"
	authURL = "https://auth.mythic-beasts.com/login"
)

// Logs into mythic beasts to acquire a bearer token for use in future API calls.
// https://www.mythic-beasts.com/support/api/auth#sec-obtaining-a-token
func (p *Provider) login(ctx context.Context) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	// Check if token is present and valid (with 30s buffer)
	if p.token.Token != "" && time.Now().Add(30*time.Second).Before(p.tokenExpiresAt) {
		return nil
	}

	params := url.Values{}
	params.Add("grant_type", `client_credentials`)
	reqBody := strings.NewReader(params.Encode())

	req, err := http.NewRequestWithContext(ctx, "POST", authURL, reqBody)
	if err != nil {
		return fmt.Errorf("login: unknown error when creating http.NewRequest()")
	}
	req.SetBasicAuth(p.KeyID, p.Secret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("login: unknown auth error")
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {

		}
	}(resp.Body)

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("login: %w", err)
	}

	if resp.StatusCode != 200 {
		if resp.StatusCode < 400 || resp.StatusCode > 499 {
			return fmt.Errorf("login: unknown error in auth API: %d", resp.StatusCode)
		}

		errResp := &mythicAuthResponseError{}
		err = json.Unmarshal(body, errResp)
		if err != nil {
			return fmt.Errorf("login: error parsing error: %w", err)
		}

		return fmt.Errorf("login: %d: %s", resp.StatusCode, errResp.ErrorMessage+errResp.ErrorDescription)
	}

	authResp := mythicAuthResponse{}
	err = json.Unmarshal(body, &authResp)
	if err != nil {
		return fmt.Errorf("login: error parsing response: %w", err)
	}

	if authResp.TokenType != "bearer" {
		return fmt.Errorf("login: received unexpected token type: %s", authResp.TokenType)
	}

	p.token = authResp
	// Set expiration time based on Lifetime (in seconds). Default to a safe fallback if 0?
	// Specs usually say expires_in.
	if authResp.Lifetime > 0 {
		p.tokenExpiresAt = time.Now().Add(time.Duration(authResp.Lifetime) * time.Second)
	} else {
		// Fallback or assume indefinitely? Let's check docs or be safe.
		// If 0, maybe it doesn't expire. But let's assume it does to be safe, e.g. 1 hour.
		p.tokenExpiresAt = time.Now().Add(1 * time.Hour)
	}

	// Success
	return nil
}

// doAPIRequest handles the common logic for making authenticated API requests
func (p *Provider) doAPIRequest(ctx context.Context, method, url string, body io.Reader) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("NewRequestWithContext: %s", err.Error())
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.token.Token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http.DefaultClient.Do: %s", err.Error())
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("ioutil.ReadAll: %w", err)
	}

	if resp.StatusCode != 200 {
		if resp.StatusCode == 401 {
			p.token.Token = ""
			p.tokenExpiresAt = time.Time{}
		}

		errResp := &mythicError{}
		errorsResp := &mythicErrors{}

		err := json.Unmarshal(respBody, errorsResp)
		if err != nil {
			err := json.Unmarshal(respBody, errResp)
			if err != nil {
				return nil, fmt.Errorf("api error: %d", resp.StatusCode)
			}
			return nil, fmt.Errorf("%d: %s", resp.StatusCode, errResp.Error)
		}
		return nil, fmt.Errorf("%d: %s", resp.StatusCode, errorsResp.Errors)
	}

	return respBody, nil
}

func (p *Provider) addRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	var addedRecords []libdns.Record

	data := mythicRecords{}
	var err = data.FromLibdns(records)
	if err != nil {
		return nil, fmt.Errorf("addRecords: Error converting libdns record to mythic record: %s", err.Error())
	}

	payload, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("addRecords: Error creating JSON payload: %s", err.Error())
	}

	respBody, err := p.doAPIRequest(ctx, "POST", apiURL+"/zones/"+url.PathEscape(zone)+"/records", bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("addRecords: %w", err)
	}

	appendResp := mythicRecordUpdate{}
	err = json.Unmarshal(respBody, &appendResp)
	if err != nil {
		return nil, fmt.Errorf("addRecords: error parsing response: %w", err)
	}

	// Assuming all were added if successful.
	addedRecords = append(addedRecords, records...)
	return addedRecords, nil
}

func (p *Provider) setRecordsAtomic(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	var setRecords []libdns.Record

	if len(records) == 0 {
		return setRecords, nil
	}

	data := mythicRecords{}
	var err = data.FromLibdns(records)
	if err != nil {
		return nil, fmt.Errorf("setRecordsAtomic: Error converting libdns records to mythic records: %s", err.Error())
	}

	payload, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("setRecordsAtomic: Error creating JSON payload: %s", err.Error())
	}

	// Build query parameters for atomic replacement
	// We need to select all host/type pairs being set.
	values := url.Values{}
	seen := make(map[string]bool)

	for _, rec := range records {
		rr := rec.RR()
		// Determine host relative to zone.
		// SetRecords guarantees Name is relative to zone.
		host := rr.Name

		key := host + "|" + rr.Type
		if seen[key] {
			continue
		}
		seen[key] = true

		if host == "" || host == "@" {
			host = "@"
		}

		val := fmt.Sprintf("host=%s&type=%s", host, rr.Type)
		values.Add("select", val)
	}

	reqURL := apiURL + "/zones/" + url.PathEscape(zone) + "/records?" + values.Encode()

	respBody, err := p.doAPIRequest(ctx, "PUT", reqURL, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("setRecordsAtomic: %w", err)
	}

	appendResp := mythicRecordUpdate{}
	err = json.Unmarshal(respBody, &appendResp)
	if err != nil {
		return nil, fmt.Errorf("setRecordsAtomic: error parsing response: %w", err)
	}

	setRecords = append(setRecords, records...)
	return setRecords, nil
}

func (p *Provider) removeRecord(ctx context.Context, zone string, record libdns.Record) ([]libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	var removedRecords []libdns.Record

	data := mythicRecords{}
	var err = data.FromLibdns([]libdns.Record{record})
	if err != nil {
		return nil, fmt.Errorf("removeRecord: Error converting libdns record to mythic record: %s", err.Error())
	}

	reqURL := apiURL + "/zones/" + url.PathEscape(zone) + "/records/" +
		url.PathEscape(data.Records[0].GetName()) + "/" +
		url.PathEscape(data.Records[0].GetType()) +
		"?exclude-template&exclude-generated"

	respBody, err := p.doAPIRequest(ctx, "DELETE", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("removeRecord: %w", err)
	}

	appendResp := mythicRecordUpdate{}
	err = json.Unmarshal(respBody, &appendResp)
	if err != nil {
		return nil, fmt.Errorf("removeRecord: error parsing response: %w", err)
	}

	if appendResp.RecordsRemoved == 1 {
		removedRecords = append(removedRecords, record)
	}
	return removedRecords, nil
}
