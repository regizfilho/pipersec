package strongswan

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

// ChildStat holds the live counters of a negotiated CHILD_SA.
type ChildStat struct {
	Name       string `json:"name"`
	State      string `json:"state"`
	LocalTS    string `json:"local_ts"`
	RemoteTS   string `json:"remote_ts"`
	BytesIn    uint64 `json:"bytes_in"`
	BytesOut   uint64 `json:"bytes_out"`
	PacketsIn  uint64 `json:"packets_in"`
	PacketsOut uint64 `json:"packets_out"`
}

// SASStats is the parsed view of `swanctl --list-sas --raw` for one IKE SA.
type SASStats struct {
	IKEState  string      `json:"ike_state"`
	Vip       string      `json:"vip"`
	Connected bool        `json:"connected"`
	Children  []ChildStat `json:"children"`
}

var (
	ikeStateRe = regexp.MustCompile(`state=(\w+)`)
	vipRe      = regexp.MustCompile(`local-vips=\[([^\]]*)\]`)
	childName  = regexp.MustCompile(`name=([A-Za-z0-9_.-]+)`)
	childStats = regexp.MustCompile(`state=(\w+).*?bytes-in=(\d+)\s+packets-in=(\d+).*?bytes-out=(\d+)\s+packets-out=(\d+)`)
	childTS    = regexp.MustCompile(`local-ts=\[([^\]]*)\] remote-ts=\[([^\]]*)\]`)
)

// ParseSASRaw parses the proprietary swanctl --raw serialization into a
// structured representation suitable for the graphical UI.
func ParseSASRaw(raw string) SASStats {
	var out SASStats
	if m := ikeStateRe.FindStringSubmatch(raw); len(m) == 2 {
		out.IKEState = m[1]
	}
	out.Connected = out.IKEState == "ESTABLISHED"
	if m := vipRe.FindStringSubmatch(raw); len(m) == 2 {
		out.Vip = m[1]
	}
	idx := strings.Index(raw, "child-sas {")
	if idx < 0 {
		return out
	}
	body := raw[idx+len("child-sas {"):]
	for {
		open := strings.Index(body, "{")
		if open < 0 {
			break
		}
		depth, end := 0, -1
		for i := open; i < len(body); i++ {
			if body[i] == '{' {
				depth++
			}
			if body[i] == '}' {
				depth--
				if depth == 0 {
					end = i
					break
				}
			}
		}
		if end < 0 {
			break
		}
		inner := body[open+1 : end]
		var c ChildStat
		if m := childName.FindStringSubmatch(inner); len(m) == 2 {
			c.Name = m[1]
		} else {
			body = body[end+1:]
			continue
		}
		if m := childStats.FindStringSubmatch(inner); len(m) == 6 {
			c.State = m[1]
			c.BytesIn, _ = strconv.ParseUint(m[2], 10, 64)
			c.PacketsIn, _ = strconv.ParseUint(m[3], 10, 64)
			c.BytesOut, _ = strconv.ParseUint(m[4], 10, 64)
			c.PacketsOut, _ = strconv.ParseUint(m[5], 10, 64)
		}
		if m := childTS.FindStringSubmatch(inner); len(m) == 3 {
			c.LocalTS = m[1]
			c.RemoteTS = m[2]
		}
		out.Children = append(out.Children, c)
		body = body[end+1:]
	}
	return out
}

// JSON serializes the stats for consumption by the graphical UI.
func (s SASStats) JSON() string {
	b, _ := json.Marshal(s)
	return string(b)
}