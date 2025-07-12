package mythicbeasts

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/libdns/libdns"
)

type mythicAuthResponse struct {
	Token     string `json:"access_token,omitempty"` // The bearer token for use in API requests
	Lifetime  int    `json:"expires_in,omitempty"`   // The maximum lifetime of the token in seconds
	TokenType string `json:"token_type,omitempty"`   // The token type must be 'bearer'
}

type mythicAuthResponseError struct {
	ErrorMessage     string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}

type mythicRecordType interface {
	GetName() string
	GetLibdnsRecord() (libdns.Record, error)
}

type mythicRecord struct {
	Type  string `json:"type,omitempty"`
	Name  string `json:"host,omitempty"`
	Value string `json:"data,omitempty"`
	TTL   int    `json:"ttl,omitempty"`
}

func (r mythicRecord) GetName() string {
	return r.Name
}
func (r mythicRecord) GetLibdnsRecord() (libdns.Record, error) {
	return libdns.RR{
		Type: r.Type,
		Name: r.Name,
		Data: r.Value,
		TTL:  time.Duration(r.TTL) * time.Second,
	}.Parse()
}

type mythicMxRecord struct {
	mythicRecord
	Priority uint16 `json:"mx_priority,omitempty"` // The priority of the MX record
}

func (r mythicMxRecord) GetName() string {
	return r.Name
}
func (r mythicMxRecord) GetLibdnsRecord() (libdns.Record, error) {
	return libdns.MX{
		Name:       r.Name,
		TTL:        time.Duration(r.TTL) * time.Second,
		Preference: r.Priority,
		Target:     r.Value,
	}, nil
}

type mythicRecords struct {
	Records []mythicRecordType `json:"records,omitempty"`
}

func (mrl *mythicRecords) UnmarshalJSON(data []byte) error {
	var untypedRecords struct {
		Records []json.RawMessage `json:"records,omitempty"`
	}

	if err := json.Unmarshal(data, &untypedRecords); err != nil {
		return err
	}

	mrl.Records = make([]mythicRecordType, len(untypedRecords.Records))

	for r, rawRecord := range untypedRecords.Records {
		// First unmarshal just to get the type
		var base mythicRecord

		if err := json.Unmarshal(rawRecord, &base); err != nil {
			fmt.Errorf("failed to unmarshal base fields for item %d: %w", r, err)
		}

		switch base.Type {
		case "A", "AAAA", "ANAME", "CNAME", "DNAME", "NS", "PTR", "TXT":
			var record mythicRecord
			if err := json.Unmarshal(rawRecord, &record); err != nil {
				return fmt.Errorf("failed to unmarshal record of type %s: %v", base.Type, err)
			}
			mrl.Records[r] = record
		case "MX":
			var mxRecord mythicMxRecord
			if err := json.Unmarshal(rawRecord, &mxRecord); err != nil {
				return fmt.Errorf("failed to unmarshal MX record: %v", err)
			}
			mrl.Records[r] = mxRecord
		default:
			return fmt.Errorf("unknown type: %s", base.Type)
		}
	}

	return nil
}
func (mrl *mythicRecords) FromLibdns(libdnsrecords []libdns.RR) error {
	return errors.New("not implemented")
}

type mythicRecordUpdate struct {
	Message        string `json:"message,omitempty"`
	RecordsAdded   int    `json:"records_added,omitempty"`
	RecordsRemoved int    `json:"records_removed,omitempty"`
}

type mythicError struct {
	Error string `json:"error,omitempty"`
}

type mythicErrors struct {
	Errors []string `json:",omitempty"`
}
