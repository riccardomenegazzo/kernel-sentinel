package loki

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Entry struct {
	Timestamp string            `json:"timestamp"`
	Line      string            `json:"line"`
	Labels    map[string]string `json:"labels,omitempty"`
}

type Client struct {
	BaseURL     string
	BearerToken string
	HTTP        *http.Client
}

func New(baseURL string) *Client {
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), HTTP: &http.Client{Timeout: 10 * time.Second}}
}

func (c *Client) QueryRange(ctx context.Context, logQL string, start, end time.Time, limit int) ([]Entry, error) {
	if c == nil || c.BaseURL == "" {
		return nil, nil
	}
	u, err := url.Parse(c.BaseURL + "/loki/api/v1/query_range")
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("query", logQL)
	q.Set("start", strconv.FormatInt(start.UnixNano(), 10))
	q.Set("end", strconv.FormatInt(end.UnixNano(), 10))
	q.Set("direction", "backward")
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	if c.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.BearerToken)
	}
	h := c.HTTP
	if h == nil {
		h = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := h.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("loki HTTP %s", resp.Status)
	}
	var body struct {
		Status string `json:"status"`
		Data   struct {
			ResultType string `json:"resultType"`
			Result     []struct {
				Stream map[string]string `json:"stream"`
				Values [][]string        `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	if body.Status != "success" {
		return nil, fmt.Errorf("loki query failed")
	}
	if body.Data.ResultType != "streams" {
		return nil, fmt.Errorf("Loki query must return log streams, got %q", body.Data.ResultType)
	}
	out := make([]Entry, 0)
	for _, s := range body.Data.Result {
		for _, v := range s.Values {
			if len(v) != 2 {
				continue
			}
			out = append(out, Entry{Timestamp: v[0], Line: v[1], Labels: s.Stream})
		}
	}
	return out, nil
}
