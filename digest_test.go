package httpdigest

import (
	"fmt"
	"net/http"
	"testing"
)

const (
	urlFormat = "http://httpbin.org/digest-auth/auth/%s/%s"
	username = "testuser"
	password = "testpassword"
)

func TestSuccessAuth(t *testing.T) {
	transport := NewDigestTransport(username, password, http.DefaultTransport)
	client := &http.Client{
		Transport: transport,
	}

	req, err := http.NewRequest(http.MethodGet, makeUrl(), nil)
	if err != nil {
		t.Error(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Error(err)
	} else {
		if resp.Body != nil {
			defer resp.Body.Close()
		}
	}
}

func makeUrl() string {
	return fmt.Sprintf(urlFormat, username, password)
}
