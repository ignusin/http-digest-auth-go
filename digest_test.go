package httpdigest

import (
	"fmt"
	"net/http"
	"testing"
)

const (
	urlFormat = "http://httpbin.org/digest-auth/auth/%s/%s"
	username  = "testuser"
	password  = "testpassword"
	times     = 2
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
	if resp.StatusCode != 200 {
		t.Error("resp.StatusCode != 200")
	}

	if err != nil {
		t.Error(err)
	} else {
		if resp.Body != nil {
			defer resp.Body.Close()
		}
	}
}

func TestSuccessAuthMultipleSameRequest(t *testing.T) {
	transport := NewDigestTransport(username, password, http.DefaultTransport)
	client := &http.Client{
		Transport: transport,
	}

	req, err := http.NewRequest(http.MethodGet, makeUrl(), nil)
	if err != nil {
		t.Error(err)
	}

	for i := 0; i < times; i++ {
		resp, err := client.Do(req)
		if resp.StatusCode != 200 {
			t.Error("resp.StatusCode != 200")
		}

		if err != nil {
			t.Error(err)
		} else {
			if resp.Body != nil {
				defer resp.Body.Close()
			}
		}
	}
}

func TestSuccessAuthMultipleDifferentRequest(t *testing.T) {
	transport := NewDigestTransport(username, password, http.DefaultTransport)
	client := &http.Client{
		Transport: transport,
	}

	for i := 0; i < times; i++ {
		req, err := http.NewRequest(http.MethodGet, makeUrl(), nil)
		if err != nil {
			t.Error(err)
		}

		resp, err := client.Do(req)
		if resp.StatusCode != 200 {
			t.Error("resp.StatusCode != 200")
		}

		if err != nil {
			t.Error(err)
		} else {
			if resp.Body != nil {
				defer resp.Body.Close()
			}
		}
	}
}

func TestNonSuccessAuth(t *testing.T) {
	wrongPassword := password + "X"

	transport := NewDigestTransport(username, wrongPassword, http.DefaultTransport)
	client := &http.Client{
		Transport: transport,
	}

	req, err := http.NewRequest(http.MethodGet, makeUrl(), nil)
	if err != nil {
		t.Error(err)
	}

	resp, err := client.Do(req)
	if resp.StatusCode != 401 {
		t.Error("resp.StatusCode != 401")
	}

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
