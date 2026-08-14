package kubernetes

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPlanRollbackAndDryRun(t *testing.T) {
	var patchSeen bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/deployments/web"):
			fmt.Fprint(w, `{"metadata":{"name":"web","namespace":"prod","uid":"dep1","resourceVersion":"42","generation":5,"annotations":{"deployment.kubernetes.io/revision":"5"}},"spec":{"replicas":3,"selector":{"matchLabels":{"app":"web"}},"template":{"spec":{"containers":[{"name":"app","image":"app:v5"}]}}},"status":{"readyReplicas":3,"updatedReplicas":3,"availableReplicas":3,"observedGeneration":5}}`)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/replicasets"):
			fmt.Fprint(w, `{"items":[{"metadata":{"name":"web-5","annotations":{"deployment.kubernetes.io/revision":"5"},"creationTimestamp":"2026-08-14T12:30:00Z","ownerReferences":[{"uid":"dep1","kind":"Deployment","name":"web"}]},"spec":{"template":{"spec":{"containers":[{"name":"app","image":"app:v5"}]}}}},{"metadata":{"name":"web-4","annotations":{"deployment.kubernetes.io/revision":"4"},"creationTimestamp":"2026-08-14T12:00:00Z","ownerReferences":[{"uid":"dep1","kind":"Deployment","name":"web"}]},"spec":{"template":{"spec":{"containers":[{"name":"app","image":"app:v4"}]}}}},{"metadata":{"name":"web-3","annotations":{"deployment.kubernetes.io/revision":"3"},"creationTimestamp":"2026-08-14T11:00:00Z","ownerReferences":[{"uid":"dep1","kind":"Deployment","name":"web"}]},"spec":{"template":{"spec":{"containers":[{"name":"app","image":"app:v3"}]}}}}]}`)
		case r.Method == http.MethodPatch && strings.HasSuffix(r.URL.Path, "/deployments/web"):
			if r.URL.Query().Get("dryRun") != "All" {
				t.Fatalf("missing dryRun")
			}
			if r.Header.Get("Content-Type") != "application/strategic-merge-patch+json" {
				t.Fatalf("content-type")
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			patchSeen = true
			fmt.Fprint(w, `{}`)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.String())
		}
	}))
	defer ts.Close()
	c := New(ts.URL, "", ts.Client())
	plan, err := c.PlanRollback(context.Background(), "prod", "web")
	if err != nil {
		t.Fatal(err)
	}
	if plan.PreviousRevision != 4 || plan.PreviousImages["app"] != "app:v4" {
		t.Fatalf("plan=%+v", plan)
	}
	if err := c.PatchImages(context.Background(), plan, plan.PreviousImages, true); err != nil {
		t.Fatal(err)
	}
	if !patchSeen {
		t.Fatal("patch not seen")
	}
}
