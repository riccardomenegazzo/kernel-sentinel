package tempo

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Trace struct {
	TraceID         string  `json:"trace_id"`
	RootServiceName string  `json:"root_service_name"`
	RootTraceName   string  `json:"root_trace_name"`
	DurationMs      float64 `json:"duration_ms"`
}

type Client struct {
	BaseURL     string
	BearerToken string
	HTTP        *http.Client
}

func New(baseURL string) *Client {
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), HTTP: &http.Client{Timeout: 10 * time.Second}}
}

func (c *Client) Search(ctx context.Context, traceQL string, start, end time.Time, limit int) ([]Trace, error) {
	if c.BaseURL == "" {
		return nil, nil
	}
	u, err := url.Parse(c.BaseURL + "/api/search")
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("q", traceQL)
	if !start.IsZero() {
		q.Set("start", fmt.Sprint(start.Unix()))
	}
	if !end.IsZero() {
		q.Set("end", fmt.Sprint(end.Unix()))
	}
	if limit > 0 {
		q.Set("limit", fmt.Sprint(limit))
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
		return nil, fmt.Errorf("tempo HTTP %s", resp.Status)
	}
	var body struct {
		Traces []struct {
			TraceID         string  `json:"traceID"`
			RootServiceName string  `json:"rootServiceName"`
			RootTraceName   string  `json:"rootTraceName"`
			DurationMs      float64 `json:"durationMs"`
		} `json:"traces"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	out := make([]Trace, 0, len(body.Traces))
	for _, t := range body.Traces {
		out = append(out, Trace{TraceID: t.TraceID, RootServiceName: t.RootServiceName, RootTraceName: t.RootTraceName, DurationMs: t.DurationMs})
	}
	return out, nil
}
