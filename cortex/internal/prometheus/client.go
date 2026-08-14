package prometheus

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Client struct {
	BaseURL     string
	BearerToken string
	HTTP        *http.Client
}

func New(baseURL string) *Client {
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), HTTP: &http.Client{Timeout: 10 * time.Second}}
}

type apiResponse struct {
	Status string `json:"status"`
	Error  string `json:"error"`
	Data   struct {
		ResultType string          `json:"resultType"`
		Result     json.RawMessage `json:"result"`
	} `json:"data"`
}

type vectorSample struct {
	Metric map[string]string `json:"metric"`
	Value  []json.RawMessage `json:"value"`
}

func (c *Client) Query(ctx context.Context, expr string, at time.Time) (float64, error) {
	if c.BaseURL == "" {
		return 0, fmt.Errorf("prometheus base URL is empty")
	}
	u, err := url.Parse(c.BaseURL + "/api/v1/query")
	if err != nil {
		return 0, err
	}
	q := u.Query()
	q.Set("query", expr)
	if !at.IsZero() {
		q.Set("time", at.UTC().Format(time.RFC3339Nano))
	}
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return 0, err
	}
	if c.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.BearerToken)
	}
	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return 0, fmt.Errorf("prometheus HTTP %s", resp.Status)
	}
	var out apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return 0, err
	}
	if out.Status != "success" {
		return 0, fmt.Errorf("prometheus query failed: %s", out.Error)
	}
	return scalar(out.Data.ResultType, out.Data.Result)
}

func scalar(kind string, raw json.RawMessage) (float64, error) {
	switch kind {
	case "scalar":
		var v []json.RawMessage
		if err := json.Unmarshal(raw, &v); err != nil || len(v) != 2 {
			return 0, fmt.Errorf("invalid scalar result")
		}
		return parseSample(v[1])
	case "vector":
		var v []vectorSample
		if err := json.Unmarshal(raw, &v); err != nil {
			return 0, err
		}
		if len(v) != 1 {
			return 0, fmt.Errorf("expected exactly one Prometheus series, got %d", len(v))
		}
		if len(v[0].Value) != 2 {
			return 0, fmt.Errorf("invalid vector sample")
		}
		return parseSample(v[0].Value[1])
	default:
		return 0, fmt.Errorf("unsupported Prometheus result type %q; query must reduce to one scalar/vector sample", kind)
	}
}

func parseSample(raw json.RawMessage) (float64, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return 0, err
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid Prometheus sample %q: %w", s, err)
	}
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0, fmt.Errorf("non-finite Prometheus sample %q", s)
	}
	return v, nil
}
