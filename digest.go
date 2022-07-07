package httpdigest

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

const (
	wwwAuthenticateHeader = "WWW-Authenticate"
	algorithmMD5          = "MD5"
	qopAuth               = "AUTH"
	digestAuthPrefix      = "Digest"

	tokenAlgorithm = "ALGORITHM"
	tokenRealm     = "REALM"
	tokenNonce     = "NONCE"
	tokenOpaque    = "OPAQUE"
	tokenQop       = "QOP"

	headerTemplate = "Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\",response=\"%s\""
)

// DigestTransport is the RoundTripper transport with support of HTTP Digest authentication.
type DigestTransport struct {
	username  string
	password  string
	transport http.RoundTripper
	authData  *authData
}

type authData struct {
	info     authInfo
	response string
}

type authInfo struct {
	algorithm string
	realm     string
	nonce     string
	opaque    string
	qop       string
}

// NewDigestTransport constructs new instance of DigestTransport.
func NewDigestTransport(username, password string,
	transport http.RoundTripper) *DigestTransport {

	return &DigestTransport{
		username:  username,
		password:  password,
		transport: transport,
	}
}

// RoundTrip is the implementation of RoundTripper interface for DigestTransport.
func (d *DigestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	authReq := *req

	if d.authData == nil {
		authResp, err := d.transport.RoundTrip(&authReq)
		if err != nil {
			return nil, err
		}

		if authResp.StatusCode != 401 {
			return authResp, nil
		}

		if authResp.Body != nil {
			defer authResp.Body.Close()
		}

		authInfo, err := parseAuthInfo(authResp.Header)
		if err != nil {
			return nil, err
		}

		authData := calculateAuthValues(req, d, authInfo)
		d.authData = &authData
	}

	assignAuthHeaders(req, d)

	return d.transport.RoundTrip(req)
}

func parseAuthInfo(h http.Header) (authInfo, error) {
	values, ok := h[http.CanonicalHeaderKey(wwwAuthenticateHeader)]
	if !ok || len(values) < 1 {
		return authInfo{}, fmt.Errorf("could not find %s header", wwwAuthenticateHeader)
	}

	value := values[0][len(digestAuthPrefix):]

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

	algorithm, ok := tokenMap[tokenAlgorithm]
	if ok && strings.ToUpper(algorithm) != algorithmMD5 {
		return authInfo{}, fmt.Errorf("not supported algorithm %s", algorithm)
	} else {
		algorithm = algorithmMD5
	}

	realm, ok := tokenMap[tokenRealm]
	if !ok {
		return authInfo{}, errors.New("no realm specified")
	}

	nonce, ok := tokenMap[tokenNonce]
	if !ok {
		return authInfo{}, errors.New("no nonce specified")
	}

	opaque, ok := tokenMap[tokenOpaque]
	if !ok {
		return authInfo{}, errors.New("no opaque specified")
	}

	qop, ok := tokenMap[tokenQop]
	if !ok {
		return authInfo{}, errors.New("no qop specified")
	} else if strings.ToUpper(qop) != qopAuth {
		return authInfo{}, fmt.Errorf("unsupported qop type: %s", qop)
	}

	result := authInfo{
		algorithm: algorithm,
		realm:     realm,
		nonce:     nonce,
		qop:       qop,
		opaque:    opaque,
	}

	return result, nil
}

func calculateAuthValues(req *http.Request, d *DigestTransport, ai authInfo) authData {
	ha1 := computeHA1(d.username, d.password, ai.realm)
	ha2 := computeHA2(req.Method, req.URL.Path)
	response := computeResponse(ha1, ha2, ai.nonce)

	return authData{
		info:     ai,
		response: response,
	}
}

func computeHA1(username, password, realm string) string {
	return computeMD5Hash(username, realm, password)
}

func computeHA2(method, digestURI string) string {
	return computeMD5Hash(strings.ToUpper(method), digestURI)
}

func computeResponse(ha1, ha2, nonce string) string {
	return computeMD5Hash(ha1, nonce, ha2)
}

func computeMD5Hash(args ...string) string {
	s := ""
	for _, x := range args {
		if s == "" {
			s = x
		} else {
			s = fmt.Sprintf("%s:%s", s, x)
		}
	}

	hash := md5.Sum([]byte(s))
	return hex.EncodeToString(hash[:])
}

func assignAuthHeaders(req *http.Request, d *DigestTransport) {
	if _, ok := req.Header["Authorization"]; ok {
		return
	}

	header := fmt.Sprintf(headerTemplate, d.username, d.authData.info.realm,
		d.authData.info.nonce, req.URL.Path, d.authData.response)

	req.Header.Add("Authorization", header)
}
