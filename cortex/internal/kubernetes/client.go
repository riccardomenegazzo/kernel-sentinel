package kubernetes

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

var ErrNoPreviousRevision = errors.New("no previous deployment revision")

type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

type Deployment struct {
	Metadata struct {
		Name            string            `json:"name"`
		Namespace       string            `json:"namespace"`
		UID             string            `json:"uid"`
		ResourceVersion string            `json:"resourceVersion"`
		Generation      int64             `json:"generation"`
		Annotations     map[string]string `json:"annotations"`
	} `json:"metadata"`
	Spec struct {
		Replicas int32 `json:"replicas"`
		Selector struct {
			MatchLabels map[string]string `json:"matchLabels"`
		} `json:"selector"`
		Template struct {
			Spec struct {
				Containers []Container `json:"containers"`
			} `json:"spec"`
		} `json:"template"`
	} `json:"spec"`
	Status struct {
		ObservedGeneration int64 `json:"observedGeneration"`
		Replicas           int32 `json:"replicas"`
		UpdatedReplicas    int32 `json:"updatedReplicas"`
		ReadyReplicas      int32 `json:"readyReplicas"`
		AvailableReplicas  int32 `json:"availableReplicas"`
	} `json:"status"`
}

type Container struct {
	Name  string `json:"name"`
	Image string `json:"image"`
}

type ReplicaSet struct {
	Metadata struct {
		Name              string            `json:"name"`
		UID               string            `json:"uid"`
		Annotations       map[string]string `json:"annotations"`
		CreationTimestamp time.Time         `json:"creationTimestamp"`
		OwnerReferences   []struct {
			UID        string `json:"uid"`
			Kind       string `json:"kind"`
			Name       string `json:"name"`
			Controller *bool  `json:"controller"`
		} `json:"ownerReferences"`
	} `json:"metadata"`
	Spec struct {
		Template struct {
			Spec struct {
				Containers []Container `json:"containers"`
			} `json:"spec"`
		} `json:"template"`
	} `json:"spec"`
}

type RollbackPlan struct {
	Namespace                string            `json:"namespace"`
	Deployment               string            `json:"deployment"`
	ResourceVersion          string            `json:"resource_version"`
	CurrentRevision          int               `json:"current_revision"`
	PreviousRevision         int               `json:"previous_revision"`
	CurrentImages            map[string]string `json:"current_images"`
	PreviousImages           map[string]string `json:"previous_images"`
	DesiredReplicas          int32             `json:"desired_replicas"`
	ReadyReplicas            int32             `json:"ready_replicas"`
	CurrentRevisionCreatedAt time.Time         `json:"current_revision_created_at"`
}

type PDB struct {
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Status struct {
		DisruptionsAllowed int32 `json:"disruptionsAllowed"`
		CurrentHealthy     int32 `json:"currentHealthy"`
		DesiredHealthy     int32 `json:"desiredHealthy"`
	} `json:"status"`
}

func New(baseURL, token string, h *http.Client) *Client {
	if h == nil {
		h = &http.Client{Timeout: 15 * time.Second}
	}
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), Token: token, HTTP: h}
}

func InCluster() (*Client, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT_HTTPS")
	if port == "" {
		port = "443"
	}
	if host == "" {
		return nil, fmt.Errorf("KUBERNETES_SERVICE_HOST is not set")
	}
	tokenBytes, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return nil, err
	}
	ca, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("invalid Kubernetes CA")
	}
	h := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}}
	return New("https://"+host+":"+port, strings.TrimSpace(string(tokenBytes)), h), nil
}

func (c *Client) GetDeployment(ctx context.Context, ns, name string) (Deployment, error) {
	var d Deployment
	err := c.doJSON(ctx, http.MethodGet, "/apis/apps/v1/namespaces/"+esc(ns)+"/deployments/"+esc(name), nil, "", &d)
	return d, err
}

func (c *Client) ListReplicaSets(ctx context.Context, ns string, labels map[string]string) ([]ReplicaSet, error) {
	selector := labelSelector(labels)
	path := "/apis/apps/v1/namespaces/" + esc(ns) + "/replicasets"
	if selector != "" {
		path += "?labelSelector=" + url.QueryEscape(selector)
	}
	var out struct {
		Items []ReplicaSet `json:"items"`
	}
	if err := c.doJSON(ctx, http.MethodGet, path, nil, "", &out); err != nil {
		return nil, err
	}
	return out.Items, nil
}

func (c *Client) ListPDBs(ctx context.Context, ns string) ([]PDB, error) {
	var out struct {
		Items []PDB `json:"items"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/apis/policy/v1/namespaces/"+esc(ns)+"/poddisruptionbudgets", nil, "", &out); err != nil {
		return nil, err
	}
	return out.Items, nil
}

func (c *Client) PlanRollback(ctx context.Context, ns, name string) (RollbackPlan, error) {
	d, err := c.GetDeployment(ctx, ns, name)
	if err != nil {
		return RollbackPlan{}, err
	}
	currentRev, _ := strconv.Atoi(d.Metadata.Annotations["deployment.kubernetes.io/revision"])
	if currentRev <= 1 {
		return RollbackPlan{}, fmt.Errorf("%w: deployment %s/%s", ErrNoPreviousRevision, ns, name)
	}
	rss, err := c.ListReplicaSets(ctx, ns, d.Spec.Selector.MatchLabels)
	if err != nil {
		return RollbackPlan{}, err
	}
	type candidate struct {
		rev int
		rs  ReplicaSet
	}
	var cs []candidate
	var currentCreated time.Time
	for _, rs := range rss {
		owned := false
		for _, o := range rs.Metadata.OwnerReferences {
			if o.UID == d.Metadata.UID && o.Kind == "Deployment" {
				owned = true
				break
			}
		}
		if !owned {
			continue
		}
		rev, _ := strconv.Atoi(rs.Metadata.Annotations["deployment.kubernetes.io/revision"])
		if rev == currentRev {
			currentCreated = rs.Metadata.CreationTimestamp
		}
		if rev > 0 && rev < currentRev {
			cs = append(cs, candidate{rev: rev, rs: rs})
		}
	}
	if len(cs) == 0 {
		return RollbackPlan{}, fmt.Errorf("%w: no previous ReplicaSet found for %s/%s", ErrNoPreviousRevision, ns, name)
	}
	sort.Slice(cs, func(i, j int) bool { return cs[i].rev > cs[j].rev })
	return RollbackPlan{Namespace: ns, Deployment: name, ResourceVersion: d.Metadata.ResourceVersion, CurrentRevision: currentRev, PreviousRevision: cs[0].rev, CurrentImages: images(d.Spec.Template.Spec.Containers), PreviousImages: images(cs[0].rs.Spec.Template.Spec.Containers), DesiredReplicas: d.Spec.Replicas, ReadyReplicas: d.Status.ReadyReplicas, CurrentRevisionCreatedAt: currentCreated}, nil
}

func (c *Client) PatchImages(ctx context.Context, plan RollbackPlan, imgs map[string]string, dryRun bool) error {
	containers := make([]map[string]string, 0, len(imgs))
	names := make([]string, 0, len(imgs))
	for name := range imgs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		containers = append(containers, map[string]string{"name": name, "image": imgs[name]})
	}
	body := map[string]any{"metadata": map[string]string{"resourceVersion": plan.ResourceVersion}, "spec": map[string]any{"template": map[string]any{"metadata": map[string]any{"annotations": map[string]string{"cortex.kernel-sentinel.io/rollback-at": time.Now().UTC().Format(time.RFC3339Nano)}}, "spec": map[string]any{"containers": containers}}}}
	b, _ := json.Marshal(body)
	path := "/apis/apps/v1/namespaces/" + esc(plan.Namespace) + "/deployments/" + esc(plan.Deployment)
	if dryRun {
		path += "?dryRun=All&fieldManager=sentinel-cortex"
	}
	return c.doJSON(ctx, http.MethodPatch, path, b, "application/strategic-merge-patch+json", nil)
}

func (c *Client) WaitReady(ctx context.Context, ns, name string, interval time.Duration) error {
	if interval <= 0 {
		interval = 2 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		d, err := c.GetDeployment(ctx, ns, name)
		if err == nil && d.Status.ObservedGeneration >= d.Metadata.Generation && d.Status.ReadyReplicas >= d.Spec.Replicas && d.Status.UpdatedReplicas >= d.Spec.Replicas && d.Spec.Replicas > 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			if err != nil {
				return fmt.Errorf("rollout verification: %w: %v", ctx.Err(), err)
			}
			return ctx.Err()
		case <-t.C:
		}
	}
}

func (c *Client) doJSON(ctx context.Context, method, path string, body []byte, contentType string, out any) error {
	if c.BaseURL == "" {
		return fmt.Errorf("Kubernetes API base URL is empty")
	}
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, r)
	if err != nil {
		return err
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("Kubernetes API %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func images(cs []Container) map[string]string {
	m := map[string]string{}
	for _, c := range cs {
		m[c.Name] = c.Image
	}
	return m
}
func labelSelector(m map[string]string) string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	p := make([]string, 0, len(ks))
	for _, k := range ks {
		p = append(p, k+"="+m[k])
	}
	return strings.Join(p, ",")
}
func esc(s string) string { return url.PathEscape(s) }

// PatchCurrentImages refreshes resourceVersion before patching. It is used for
// compensating rollback when post-action verification fails.
func (c *Client) PatchCurrentImages(ctx context.Context, ns, name string, imgs map[string]string, dryRun bool) error {
	d, err := c.GetDeployment(ctx, ns, name)
	if err != nil {
		return err
	}
	p := RollbackPlan{Namespace: ns, Deployment: name, ResourceVersion: d.Metadata.ResourceVersion}
	return c.PatchImages(ctx, p, imgs, dryRun)
}
