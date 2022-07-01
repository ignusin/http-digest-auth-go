package httpdigest

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

const (
	wwwAuthenticateHeader = "WWW-Authenticate"
	algorithmMD5 = "MD5"
)

type DigestTransport struct {
	username	string
	password	string
	transport	http.RoundTripper
}

type authInfo struct {
	algorithm	string
	realm		string
	nonce		string
	opaque		string
	qop			string
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

	if resp.StatusCode != 401 {
		return resp, nil
	}

	if resp.Body != nil {
		defer resp.Body.Close()
	}

	authInfo, err := parseAuthInfo(resp.Header)
	if err != nil {
		return nil, err
	}

	fmt.Println(authInfo)

	authreq := &http.Request{}
	*authreq = *req

	return nil, errors.New("not implemented yet")
}

func parseAuthInfo(h http.Header) (*authInfo, error) {
	values, ok := h[http.CanonicalHeaderKey(wwwAuthenticateHeader)]
	if !ok || len(values) < 1 {
		return nil, fmt.Errorf("could not find %s header", wwwAuthenticateHeader)
	}

	value := values[0][len("DIGEST "):]
	
	tokens := strings.Split(value, ",")
	tokenMap := make(map[string]string)

	for _, token := range tokens {
		tokenKeyValue := strings.Split(strings.TrimSpace(token), "=")
		if len(tokenKeyValue) != 2 {
			continue
		}

		tokenKey := strings.ToUpper(tokenKeyValue[0])
		tokenValue := strings.Trim(tokenKeyValue[1], "\"")

		tokenMap[tokenKey] = tokenValue
	}

	algorithm, ok := tokenMap["ALGORITHM"]
	if ok && strings.ToUpper(algorithm) != algorithmMD5 {
		return nil, fmt.Errorf("not supported algorithm %s", algorithm)
	} else if !ok {
		algorithm = algorithmMD5
	}

	realm, ok := tokenMap["REALM"]
	if !ok {
		return nil, errors.New("no realm specified")
	}

	nonce, ok := tokenMap["NONCE"]
	if !ok {
		return nil, errors.New("no nonce specified")
	}

	opaque, ok := tokenMap["OPAQUE"]
	if !ok {
		return nil, errors.New("no opaque specified")
	}

	qop, ok := tokenMap["QOP"]
	if !ok {
		return nil, errors.New("no qop specified")
	}

	result := &authInfo{
		algorithm: algorithm,
		realm: realm,
		nonce: nonce,
		qop: qop,
		opaque: opaque,
	}

	return result, nil
}