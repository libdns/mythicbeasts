package mythicbeasts

import (
	"encoding/json"
	"fmt"
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
func (p *Provider) login() error {
	if p.token.Token != "" {
		// Already authenticated, stop now
		return nil
	}

	params := url.Values{}
	params.Add("grant_type", `client_credentials`)
	reqBody := strings.NewReader(params.Encode())

	req, err := http.NewRequest("POST", authURL, reqBody)
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
