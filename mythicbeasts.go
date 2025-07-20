package mythicbeasts

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
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
	GetType() string
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
func (r mythicRecord) GetType() string {
	return r.Type
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
func (r mythicMxRecord) GetType() string {
	return r.Type
}
func (r mythicMxRecord) GetLibdnsRecord() (libdns.Record, error) {
	return libdns.MX{
		Name:       r.Name,
		TTL:        time.Duration(r.TTL) * time.Second,
		Preference: r.Priority,
		Target:     r.Value,
	}, nil
}

type mythicCaaRecord struct {
	mythicRecord
	Flags uint8  `json:"caa_flags,omitempty"`
	Tag   string `json:"caa_tag,omitempty"`
}

func (r mythicCaaRecord) GetName() string {
	return r.Name
}
func (r mythicCaaRecord) GetType() string {
	return r.Type
}
func (r mythicCaaRecord) GetLibdnsRecord() (libdns.Record, error) {
	return libdns.CAA{
		Name:  r.Name,
		TTL:   time.Duration(r.TTL) * time.Second,
		Flags: r.Flags,
		Tag:   r.Tag,
		Value: r.Value,
	}, nil
}

type mythicSrvRecord struct {
	mythicRecord
	Priority uint16 `json:"srv_priority,omitempty"`
	Weight   uint16 `json:"srv_weight,omitempty"`
	Port     uint16 `json:"srv_port,omitempty"`
}

func (r mythicSrvRecord) GetName() string {
	return r.Name
}
func (r mythicSrvRecord) GetType() string {
	return r.Type
}
func (r mythicSrvRecord) GetLibdnsRecord() (libdns.Record, error) {
	nameParts := strings.Split(r.Name, ".")
	return libdns.SRV{
		Service:   strings.TrimPrefix(nameParts[0], "_"),
		Transport: strings.TrimPrefix(nameParts[1], "_"),
		Name:      nameParts[2],
		TTL:       time.Duration(r.TTL) * time.Second,
		Priority:  r.Priority,
		Weight:    r.Weight,
		Port:      r.Port,
		Target:    r.Value,
	}, nil
}

type mythicSshfpRecord struct {
	mythicRecord
	Algorithm uint8 `json:"sshfp_algorithm,omitempty"`
	SshfpType uint8 `json:"sshfp_type,omitempty"`
}

func (r mythicSshfpRecord) GetName() string {
	return r.Name
}
func (r mythicSshfpRecord) GetType() string {
	return r.Type
}
func (r mythicSshfpRecord) GetLibdnsRecord() (libdns.Record, error) {
	return libdns.RR{
		Name: r.Name,
		TTL:  time.Duration(r.TTL) * time.Second,
		Type: "SSHFP",
		Data: fmt.Sprintf("%d %d %s", r.Algorithm, r.SshfpType, r.Value),
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
			return fmt.Errorf("failed to unmarshal base fields for item %d: %w", r, err)
		}

		switch base.Type {
		case "A", "AAAA", "CNAME", "NS", "PTR", "TXT":
			mrl.Records[r] = base
		case "ANAME", "DNAME": // Unoffical types
			mrl.Records[r] = base
		case "TLSA": // Offical types, but not supported by libdns
			mrl.Records[r] = base
		case "MX":
			var mxRecord mythicMxRecord
			if err := json.Unmarshal(rawRecord, &mxRecord); err != nil {
				return fmt.Errorf("failed to unmarshal MX record: %v", err)
			}
			mrl.Records[r] = mxRecord
		case "CAA":
			var caaRecord mythicCaaRecord
			if err := json.Unmarshal(rawRecord, &caaRecord); err != nil {
				return fmt.Errorf("failed to unmarshal CAA record: %v", err)
			}
			mrl.Records[r] = caaRecord
		case "SRV":
			var srvRecord mythicSrvRecord
			if err := json.Unmarshal(rawRecord, &srvRecord); err != nil {
				return fmt.Errorf("failed to unmarshal SRV record: %v", err)
			}
			mrl.Records[r] = srvRecord
		case "SSHFP":
			var sshfpRecord mythicSshfpRecord
			if err := json.Unmarshal(rawRecord, &sshfpRecord); err != nil {
				return fmt.Errorf("failed to unmarshal SSHFP record: %v", err)
			}
			mrl.Records[r] = sshfpRecord
		default:
			return fmt.Errorf("unknown type: %s", base.Type)
		}
	}

	return nil
}
func (mrl *mythicRecords) FromLibdns(libdnsrecords []libdns.Record) error {
	for _, record := range libdnsrecords {
		var rr = record.RR()

		var mr mythicRecord
		mr.Type = rr.Type
		mr.Name = rr.Name
		mr.Value = rr.Data
		mr.TTL = int(rr.TTL.Seconds())

		switch r := record.(type) {
		case libdns.Address, libdns.CNAME, libdns.NS, libdns.TXT:
			mrl.Records = append(mrl.Records, mr)
		case libdns.RR:
			if rr.Type == "SSHFP" {
				valueParts := strings.Split(rr.Data, " ")
				algorithm, err := strconv.ParseUint(valueParts[0], 10, 8)
				if err != nil {
					return fmt.Errorf("FromLibdns: failed to parse SSHFP algorithm: %w", err)
				}
				sshfptype, err := strconv.ParseUint(valueParts[1], 10, 8)
				if err != nil {
					return fmt.Errorf("FromLibdns: failed to parse SSHFP type: %w", err)
				}
				sshfp := mythicSshfpRecord{
					mythicRecord: mr,
					Algorithm:    uint8(algorithm),
					SshfpType:    uint8(sshfptype),
				}
				sshfp.Value = valueParts[2]
				mrl.Records = append(mrl.Records, sshfp)
				continue
			} else {
				mrl.Records = append(mrl.Records, mr)
			}
		case libdns.MX:
			var mxr mythicMxRecord
			mxr = mythicMxRecord{
				mythicRecord: mr,
				Priority:     r.Preference,
			}
			mxr.Value = r.Target
			mrl.Records = append(mrl.Records, mxr)
		case libdns.CAA:
			var caar mythicCaaRecord
			caar = mythicCaaRecord{
				mythicRecord: mr,
				Flags:        r.Flags,
				Tag:          r.Tag,
			}
			caar.Value = r.Value
			mrl.Records = append(mrl.Records, caar)
		case libdns.SRV:
			var srvr mythicSrvRecord
			srvr = mythicSrvRecord{
				mythicRecord: mr,
				Priority:     r.Priority,
				Weight:       r.Weight,
				Port:         r.Port,
			}
			srvr.Name = fmt.Sprintf("_%s._%s.%s", r.Service, r.Transport, r.Name)
			srvr.Value = r.Target
			mrl.Records = append(mrl.Records, srvr)
		default:
			return fmt.Errorf("FromLibdns: unknown record type %T", r)
		}
	}

	return nil
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
