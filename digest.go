package httpdigest

import (
	"errors"
	"net/http"
)

type DigestTransport struct {
	username string
	password string
	transport http.RoundTripper
}

func NewDigestTransport(username, password string,
	transport http.RoundTripper) *DigestTransport {
	
	return &DigestTransport{
		username: username,
		password: password,
		transport: transport,
	}
}

func (dt *DigestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := dt.transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == 401 {
		if resp.Body != nil {
			defer resp.Body.Close()
		}

		return nil, errors.New("needs authentication")
	}

	return resp, nil
}
