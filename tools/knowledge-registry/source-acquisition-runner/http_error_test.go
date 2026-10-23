package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

type failedResponseBody struct{ err error }

func (b failedResponseBody) Read([]byte) (int, error) { return 0, b.err }
func (b failedResponseBody) Close() error             { return nil }

func TestGitObjectStatusError(t *testing.T) {
	failedRead := errors.New("response read failed")
	cases := []struct {
		name   string
		status int
		body   io.ReadCloser
		want   error
	}{
		{"success", http.StatusOK, io.NopCloser(strings.NewReader("{}")), nil},
		{"http failure", http.StatusForbidden, io.NopCloser(strings.NewReader("denied")), nil},
		{"drain failure", http.StatusForbidden, failedResponseBody{failedRead}, failedRead},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := gitObjectStatusError(&http.Response{StatusCode: tc.status, Body: tc.body})
			if (got == nil) != (tc.status == http.StatusOK) {
				t.Fatalf("status error = %v", got)
			}
			if tc.want != nil && !errors.Is(got, tc.want) {
				t.Fatalf("lost drain error: %v", got)
			}
		})
	}
}

type responseTransport func(*http.Request) (*http.Response, error)

func (f responseTransport) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

type closeErrorBody struct {
	io.Reader
	err error
}

func (b closeErrorBody) Close() error { return b.err }

func TestGetJSONPreservesResponseCloseError(t *testing.T) {
	cleanup := errors.New("response close failed")
	for _, closeErr := range []error{nil, cleanup} {
		origin, err := url.Parse("https://api.github.com")
		if err != nil {
			t.Fatal(err)
		}
		client := &http.Client{Transport: responseTransport(func(req *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Request: req, Body: closeErrorBody{strings.NewReader("{}"), closeErr}}, nil
		})}
		r := &runner{client: client, baseURL: origin}
		err = r.getJSON(context.Background(), "argoproj/argo-helm", "/git/test", &map[string]any{})

		if !errors.Is(err, closeErr) {
			t.Fatalf("response close error = %v, want %v", err, closeErr)
		}
	}
}
