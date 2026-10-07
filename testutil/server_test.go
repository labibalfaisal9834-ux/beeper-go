package testutil

import (
	"bytes"
	"io"
	"net/http"
	"testing"
)

func TestEchoServer(t *testing.T) {
	server, err := LaunchServer()
	if err != nil {
		t.Fatalf("LaunchServer failed: %v", err)
	}
	defer server.Close()

	url := "http://" + server.Addr().String() + "/test"
	req, err := http.NewRequest("GET", url, bytes.NewBufferString("hello world"))
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}
	req.Header.Set("X-Custom-Header", "beeper-value")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}

	if val := resp.Header.Get("X-Custom-Header"); val != "beeper-value" {
		t.Fatalf("expected header 'beeper-value', got %q", val)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body failed: %v", err)
	}
	if string(body) != "hello world" {
		t.Fatalf("expected body 'hello world', got %q", string(body))
	}
}

func TestEchoServerNonUTF8(t *testing.T) {
	server, err := LaunchServer()
	if err != nil {
		t.Fatalf("LaunchServer failed: %v", err)
	}
	defer server.Close()

	url := "http://" + server.Addr().String() + "/test"
	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte{0xff, 0xfe, 0xfd}))
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for non-UTF8 body, got %d", resp.StatusCode)
	}
}
