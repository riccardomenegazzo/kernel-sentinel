package prometheus

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestQueryVectorScalar(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/query" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		fmt.Fprint(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1,"0.0125"]}]}}`)
	}))
	defer ts.Close()
	v, err := New(ts.URL).Query(context.Background(), "sum(rate(errors[5m]))", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if v != .0125 {
		t.Fatalf("v=%v", v)
	}
}

func TestQueryRejectsAmbiguousVector(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"a":"1"},"value":[1,"1"]},{"metric":{"a":"2"},"value":[1,"2"]}]}}`)
	}))
	defer ts.Close()
	_, err := New(ts.URL).Query(context.Background(), "x", time.Time{})
	if err == nil {
		t.Fatal("expected ambiguity error")
	}
}
