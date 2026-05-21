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
		return fmt.Errorf("login: unknown error when creating http.NewRequest()")
	}
	req.SetBasicAuth(p.KeyID, p.Secret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("login: unknown auth error")
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("login: %w", err)
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

		reqURL := apiURL + "/zones/" + url.PathEscape(formatedZone) + "/records/" + url.PathEscape(key.host) + "/" + url.PathEscape(key.rType)
		respBody, err := p.doAPIRequest(ctx, "POST", reqURL, bytes.NewReader(payload))
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

		reqURL := apiURL + "/zones/" + url.PathEscape(formatedZone) + "/records/" + url.PathEscape(key.host) + "/" + url.PathEscape(key.rType)
		respBody, err := p.doAPIRequest(ctx, "PUT", reqURL, bytes.NewReader(payload))
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
		return nil, fmt.Errorf("removeRecord: Error converting libdns record to mythic record: %s", err.Error())
	}

	reqURL := apiURL + "/zones/" + url.PathEscape(formatedZone) + "/records/" +
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
