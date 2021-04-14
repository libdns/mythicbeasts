package mythicbeasts

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/libdns/libdns"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
)

const (
	apiURL  = "https://api.mythic-beasts.com/dns/v2"
	authURL = "https://auth.mythic-beasts.com/login"
)

// Logs into mythic beasts to acquire a bearer token for use in future API calls.
// https://www.mythic-beasts.com/support/api/auth#sec-obtaining-a-token
func (p *Provider) login(ctx context.Context) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if p.token.Token != "" {
		// Already authenticated, stop now
		return nil
	}

	params := url.Values{}
	params.Add("grant_type", `client_credentials`)
	reqBody := strings.NewReader(params.Encode())

	req, err := http.NewRequestWithContext(ctx, "POST", authURL, reqBody)
	if err != nil {
		return fmt.Errorf("login: unknown error when creating http.NewRequest()")
	}
	req.SetBasicAuth(os.ExpandEnv(p.KeyID), os.ExpandEnv(p.Secret))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("login: unknown auth error")
	}
	defer resp.Body.Close()

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

		return fmt.Errorf("login: %d: %w", resp.StatusCode, errResp)
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

	// Success
	return nil
}

func (p *Provider) addRecord(ctx context.Context, zone string, record libdns.Record) ([]libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	var addedRecords []libdns.Record

	data := mythicRecords{}
	data.Records = append(data.Records, mythicRecord{Type: record.Type, Name: record.Name, Value: record.Value, TTL: int(record.TTL.Seconds())})

	payload, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("addRecord: Error creating JSON payload: %s", err.Error())
	}

	body := bytes.NewReader(payload)
	req, err := http.NewRequestWithContext(ctx, "POST", apiURL+"/zones/"+zone+"/records", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.token.Token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("addRecord: Error creating JSON payload: %s", err.Error())
	}
	defer resp.Body.Close()

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("addRecord: Failed %w", err)
	}

	if resp.StatusCode != 200 {
		errResp := &mythicError{}
		errorsResp := &mythicErrors{}

		err := json.Unmarshal(respBody, errorsResp)
		if err != nil {
			err := json.Unmarshal(respBody, errResp)
			if err != nil {
				return nil, fmt.Errorf("addRecord: unknown error: %d", resp.StatusCode)
			}
			return nil, fmt.Errorf("addRecord: %d: %w", resp.StatusCode, errResp.Error)
		}
		return nil, fmt.Errorf("addRecord: %d: %w", resp.StatusCode, errorsResp.Errors)
	}

	appendResp := mythicRecordUpdate{}
	err = json.Unmarshal(respBody, &appendResp)
	if err != nil {
		return nil, fmt.Errorf("addRecord: error parsing response: %w", err)
	}

	if appendResp.RecordsAdded == 1 {
		addedRecords = append(addedRecords, record)
	}
	return addedRecords, nil
}

func (p *Provider) updateRecord(ctx context.Context, zone string, record libdns.Record) ([]libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	return nil, nil
}

func (p *Provider) removeRecord(ctx context.Context, domain string, record libdns.Record) ([]libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	return nil, nil
}
