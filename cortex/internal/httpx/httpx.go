package httpx

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

func Client(caFile string, timeout time.Duration) (*http.Client, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		b, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read CA %s: %w", caFile, err)
		}
		if !pool.AppendCertsFromPEM(b) {
			return nil, fmt.Errorf("no certificates found in %s", caFile)
		}
		transport.TLSClientConfig.RootCAs = pool
	}
	return &http.Client{Timeout: timeout, Transport: transport}, nil
}

func Secret(direct, envName, file string) (string, error) {
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}
	if envName != "" {
		v := os.Getenv(envName)
		if v == "" {
			return "", fmt.Errorf("environment variable %s is empty", envName)
		}
		return v, nil
	}
	return direct, nil
}
