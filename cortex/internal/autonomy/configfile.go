package autonomy

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type FileConfig struct {
	Config
	PrometheusURL             string `json:"prometheus_url"`
	PrometheusBearerToken     string `json:"prometheus_bearer_token,omitempty"`
	PrometheusBearerTokenEnv  string `json:"prometheus_bearer_token_env,omitempty"`
	PrometheusBearerTokenFile string `json:"prometheus_bearer_token_file,omitempty"`
	PrometheusCAFile          string `json:"prometheus_ca_file,omitempty"`
	TempoURL                  string `json:"tempo_url,omitempty"`
	TempoBearerToken          string `json:"tempo_bearer_token,omitempty"`
	TempoBearerTokenEnv       string `json:"tempo_bearer_token_env,omitempty"`
	TempoBearerTokenFile      string `json:"tempo_bearer_token_file,omitempty"`
	TempoCAFile               string `json:"tempo_ca_file,omitempty"`
	LokiURL                   string `json:"loki_url,omitempty"`
	LokiBearerToken           string `json:"loki_bearer_token,omitempty"`
	LokiBearerTokenEnv        string `json:"loki_bearer_token_env,omitempty"`
	LokiBearerTokenFile       string `json:"loki_bearer_token_file,omitempty"`
	LokiCAFile                string `json:"loki_ca_file,omitempty"`
	AuditPath                 string `json:"audit_path,omitempty"`
	AuditHMACEnv              string `json:"audit_hmac_env,omitempty"`
	PollSeconds               int    `json:"poll_seconds,omitempty"`
	RolloutTimeoutSeconds     int    `json:"rollout_timeout_seconds,omitempty"`
	VerifyDelaySeconds        int    `json:"verify_delay_seconds,omitempty"`
	MaxRevisionAgeSeconds     int    `json:"max_revision_age_seconds,omitempty"`
	CooldownSeconds           int    `json:"cooldown_seconds,omitempty"`
}

func LoadFile(path string) (FileConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return FileConfig{}, err
	}
	var c FileConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return FileConfig{}, fmt.Errorf("decode config: %w", err)
	}
	c.Config.Defaults()
	if c.PollSeconds <= 0 {
		c.PollSeconds = 30
	}
	if c.RolloutTimeoutSeconds <= 0 {
		c.RolloutTimeoutSeconds = 120
	}
	if c.VerifyDelaySeconds <= 0 {
		c.VerifyDelaySeconds = 30
	}
	if c.MaxRevisionAgeSeconds <= 0 {
		c.MaxRevisionAgeSeconds = 1800
	}
	if c.CooldownSeconds <= 0 {
		c.CooldownSeconds = 600
	}
	c.Config.RolloutTimeout = time.Duration(c.RolloutTimeoutSeconds) * time.Second
	c.Config.VerifyDelay = time.Duration(c.VerifyDelaySeconds) * time.Second
	c.Config.MaxRevisionAge = time.Duration(c.MaxRevisionAgeSeconds) * time.Second
	c.Config.Cooldown = time.Duration(c.CooldownSeconds) * time.Second
	if err := c.Config.Validate(); err != nil {
		return FileConfig{}, err
	}
	if c.PrometheusURL == "" {
		return FileConfig{}, fmt.Errorf("prometheus_url is required")
	}
	return c, nil
}
