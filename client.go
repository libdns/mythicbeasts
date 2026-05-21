package mythicbeasts

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
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
		return fmt.Errorf("login: failed to create request: %w", err)
	}
	req.SetBasicAuth(p.KeyID, p.Secret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("login: auth request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("login: failed to read response: %w", err)
	}

	if resp.StatusCode != 200 {
		errResp := &mythicAuthResponseError{}
		if err := json.Unmarshal(body, errResp); err == nil {
			var errMsg string
			if errResp.ErrorMessage != "" && errResp.ErrorDescription != "" {
				errMsg = fmt.Sprintf("%s: %s", errResp.ErrorMessage, errResp.ErrorDescription)
			} else if errResp.ErrorMessage != "" {
				errMsg = errResp.ErrorMessage
			} else if errResp.ErrorDescription != "" {
				errMsg = errResp.ErrorDescription
			}
			if errMsg != "" {
				return fmt.Errorf("login: %d: %s", resp.StatusCode, errMsg)
			}
		}

		if len(body) > 0 {
			trimmedBody := strings.TrimSpace(string(body))
			if len(trimmedBody) > 200 {
				trimmedBody = trimmedBody[:200] + "..."
			}
			return fmt.Errorf("login: %d: %s", resp.StatusCode, trimmedBody)
		}

		return fmt.Errorf("login: unknown error in auth API: %d", resp.StatusCode)
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

// doRequest handles the common logic for making authenticated API requests
func (p *Provider) doRequest(ctx context.Context, method, endpoint string, body io.Reader) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, apiURL+endpoint, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.token.Token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("io.ReadAll: %w", err)
	}

	if resp.StatusCode != 200 {
		if resp.StatusCode == 401 {
			p.token.Token = ""
			p.tokenExpiresAt = time.Time{}
		}

		errResp := &mythicError{}
		errorsResp := &mythicErrors{}

		if err := json.Unmarshal(respBody, errorsResp); err == nil && len(errorsResp.Errors) > 0 {
			return nil, fmt.Errorf("%d: %s", resp.StatusCode, strings.Join(errorsResp.Errors, ", "))
		}

		if err := json.Unmarshal(respBody, errResp); err == nil && errResp.Error != "" {
			return nil, fmt.Errorf("%d: %s", resp.StatusCode, errResp.Error)
		}

		if len(respBody) > 0 {
			trimmedBody := strings.TrimSpace(string(respBody))
			if len(trimmedBody) > 200 {
				trimmedBody = trimmedBody[:200] + "..."
			}
			return nil, fmt.Errorf("api error %d: %s", resp.StatusCode, trimmedBody)
		}

		return nil, fmt.Errorf("api error: %d", resp.StatusCode)
	}

	return respBody, nil
}

func (p *Provider) addRecords(ctx context.Context, formatedZone string, originalZone string, records []libdns.Record) ([]libdns.Record, error) {
	type hostType struct {
		host  string
		rType string
	}

	groups := make(map[hostType][]libdns.Record)
	for _, record := range records {
		adjustedRecord := p.adjustRecordName(originalZone, formatedZone, record)
		rr := adjustedRecord.RR()
		host := rr.Name
		if host == "" {
			host = "@"
		}
		key := hostType{host: host, rType: rr.Type}
		groups[key] = append(groups[key], record)
	}

	p.mutex.Lock()
	defer p.mutex.Unlock()

	var addedRecords []libdns.Record

	for key, groupRecords := range groups {
		adjustedGroupRecords := make([]libdns.Record, len(groupRecords))
		for i, r := range groupRecords {
			adjustedGroupRecords[i] = p.adjustRecordName(originalZone, formatedZone, r)
		}

		data := mythicRecords{}
		var err = data.FromLibdns(adjustedGroupRecords)
		if err != nil {
			return nil, fmt.Errorf("addRecords: Error converting libdns record to mythic record: %w", err)
		}

		payload, err := json.Marshal(data)
		if err != nil {
			return nil, fmt.Errorf("addRecords: Error creating JSON payload: %w", err)
		}

		reqURL := "/zones/" + url.PathEscape(formatedZone) + "/records/" + url.PathEscape(key.host) + "/" + url.PathEscape(key.rType)
		respBody, err := p.doRequest(ctx, "POST", reqURL, bytes.NewReader(payload))
		if err != nil {
			return nil, fmt.Errorf("addRecords: %w", err)
		}

		appendResp := mythicRecordUpdate{}
		err = json.Unmarshal(respBody, &appendResp)
		if err != nil {
			return nil, fmt.Errorf("addRecords: error parsing response: %w", err)
		}

		addedRecords = append(addedRecords, groupRecords...)
	}

	return addedRecords, nil
}

func (p *Provider) setRecordsAtomic(ctx context.Context, formatedZone string, originalZone string, records []libdns.Record) ([]libdns.Record, error) {
	if len(records) == 0 {
		return nil, nil
	}

	type hostType struct {
		host  string
		rType string
	}

	groups := make(map[hostType][]libdns.Record)
	for _, record := range records {
		adjustedRecord := p.adjustRecordName(originalZone, formatedZone, record)
		rr := adjustedRecord.RR()
		host := rr.Name
		if host == "" {
			host = "@"
		}
		key := hostType{host: host, rType: rr.Type}
		groups[key] = append(groups[key], record)
	}

	p.mutex.Lock()
	defer p.mutex.Unlock()

	var setRecords []libdns.Record

	for key, groupRecords := range groups {
		adjustedGroupRecords := make([]libdns.Record, len(groupRecords))
		for i, r := range groupRecords {
			adjustedGroupRecords[i] = p.adjustRecordName(originalZone, formatedZone, r)
		}

		data := mythicRecords{}
		var err = data.FromLibdns(adjustedGroupRecords)
		if err != nil {
			return nil, fmt.Errorf("setRecordsAtomic: Error converting libdns records to mythic records: %w", err)
		}

		payload, err := json.Marshal(data)
		if err != nil {
			return nil, fmt.Errorf("setRecordsAtomic: Error creating JSON payload: %w", err)
		}

		reqURL := "/zones/" + url.PathEscape(formatedZone) + "/records/" + url.PathEscape(key.host) + "/" + url.PathEscape(key.rType)
		respBody, err := p.doRequest(ctx, "PUT", reqURL, bytes.NewReader(payload))
		if err != nil {
			return nil, fmt.Errorf("setRecordsAtomic: %w", err)
		}

		appendResp := mythicRecordUpdate{}
		err = json.Unmarshal(respBody, &appendResp)
		if err != nil {
			return nil, fmt.Errorf("setRecordsAtomic: error parsing response: %w", err)
		}

		setRecords = append(setRecords, groupRecords...)
	}

	return setRecords, nil
}

func (p *Provider) removeRecord(ctx context.Context, formatedZone string, originalZone string, record libdns.Record) ([]libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	var removedRecords []libdns.Record

	adjustedRecord := p.adjustRecordName(originalZone, formatedZone, record)

	data := mythicRecords{}
	var err = data.FromLibdns([]libdns.Record{adjustedRecord})
	if err != nil {
		return nil, fmt.Errorf("removeRecord: error converting libdns record to mythic record: %w", err)
	}

	reqURL := "/zones/" + url.PathEscape(formatedZone) + "/records/" +
		url.PathEscape(data.Records[0].GetName()) + "/" +
		url.PathEscape(data.Records[0].GetType()) +
		"?exclude-template&exclude-generated"

	respBody, err := p.doRequest(ctx, "DELETE", reqURL, nil)
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

// unFQDN trims any trailing "." from fqdn.
func (p *Provider) unFQDN(fqdn string) string {
	return strings.TrimSuffix(fqdn, ".")
}

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
