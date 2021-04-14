package mythicbeasts

import "time"

type mythicAuthResponse struct {
	Token     string `json:"access_token"` // The bearer token for use in API requests
	Lifetime  int    `json:"expires_in"`   // The maximum lifetime of the token in seconds
	TokenType string `json:"token_type"`   // The token type must be 'bearer'
}

type mythicAuthResponseError struct {
	ErrorMessage     string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

type mythicRecordsResponse struct {
	Records []mythicRecord `json:"records"`
}

type mythicRecord struct {
	Type  string        `json:"type,omitempty"`
	Name  string        `json:"host,omitempty"`
	Value string        `json:"data,omitempty"`
	TTL   time.Duration `json:"ttl,omitempty"`
}
