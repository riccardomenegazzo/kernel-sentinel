package audit

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

type Entry struct {
	At       time.Time       `json:"at"`
	Incident string          `json:"incident"`
	Action   string          `json:"action"`
	Payload  json.RawMessage `json:"payload,omitempty"`
	Previous string          `json:"previous,omitempty"`
	MAC      string          `json:"mac"`
}

type Chain struct {
	mu       sync.Mutex
	Path     string
	Key      []byte
	previous string
}

func New(path string, key []byte) (*Chain, error) {
	c := &Chain{Path: path, Key: append([]byte(nil), key...)}
	if path == "" {
		return c, nil
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return c, nil
	} else if err != nil {
		return nil, err
	}
	if err := Verify(path, key); err != nil {
		return nil, fmt.Errorf("verify existing audit chain: %w", err)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		var e Entry
		if json.Unmarshal(s.Bytes(), &e) == nil {
			c.previous = e.MAC
		}
	}
	return c, s.Err()
}

func (c *Chain) Append(incident, action string, payload any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Path == "" {
		return nil
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	e := Entry{At: time.Now().UTC(), Incident: incident, Action: action, Payload: b, Previous: c.previous}
	canonical, _ := json.Marshal(struct {
		At               time.Time `json:"at"`
		Incident, Action string
		Payload          json.RawMessage
		Previous         string
	}{e.At, e.Incident, e.Action, e.Payload, e.Previous})
	mac := hmac.New(sha256.New, c.Key)
	_, _ = mac.Write(canonical)
	e.MAC = hex.EncodeToString(mac.Sum(nil))
	line, _ := json.Marshal(e)
	if err := os.MkdirAll(dir(c.Path), 0750); err != nil {
		return err
	}
	f, err := os.OpenFile(c.Path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.Write(append(line, '\n')); err != nil {
		return err
	}
	c.previous = e.MAC
	return f.Sync()
}

func dir(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			if i == 0 {
				return "/"
			}
			return path[:i]
		}
	}
	return "."
}

func Verify(path string, key []byte) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	prev := ""
	line := 0
	s := bufio.NewScanner(f)
	for s.Scan() {
		line++
		var e Entry
		if err := json.Unmarshal(s.Bytes(), &e); err != nil {
			return fmt.Errorf("line %d: %w", line, err)
		}
		if e.Previous != prev {
			return fmt.Errorf("line %d: chain discontinuity", line)
		}
		canonical, _ := json.Marshal(struct {
			At               time.Time `json:"at"`
			Incident, Action string
			Payload          json.RawMessage
			Previous         string
		}{e.At, e.Incident, e.Action, e.Payload, e.Previous})
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write(canonical)
		if !hmac.Equal([]byte(e.MAC), []byte(hex.EncodeToString(mac.Sum(nil)))) {
			return fmt.Errorf("line %d: invalid MAC", line)
		}
		prev = e.MAC
	}
	return s.Err()
}
