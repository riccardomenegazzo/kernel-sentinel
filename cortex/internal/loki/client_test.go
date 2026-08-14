package loki

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestQueryRange(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/loki/api/v1/query_range" {
			t.Fatal(r.URL.Path)
		}
		fmt.Fprint(w, `{"status":"success","data":{"resultType":"streams","result":[{"stream":{"app":"x"},"values":[["1","boom"]]}]}}`)
	}))
	defer s.Close()
	v, e := New(s.URL).QueryRange(context.Background(), `{app="x"}`, time.Unix(0, 0), time.Unix(1, 0), 10)
	if e != nil {
		t.Fatal(e)
	}
	if len(v) != 1 || v[0].Line != "boom" {
		t.Fatalf("%+v", v)
	}
}
