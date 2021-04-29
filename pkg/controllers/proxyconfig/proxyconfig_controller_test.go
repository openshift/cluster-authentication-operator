package proxyconfig

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"testing"

	"golang.org/x/net/http/httpproxy"
)

func Test_isProxyConfigured(t *testing.T) {
	tests := []struct {
		name        string
		proxyConfig *httpproxy.Config
		want        bool
	}{
		{
			name: "without proxy",
		},
		{
			name: "with http proxy",
			proxyConfig: &httpproxy.Config{
				HTTPProxy: "proxy-url",
			},
			want: true,
		},
		{
			name: "with https proxy",
			proxyConfig: &httpproxy.Config{
				HTTPSProxy: "proxy-url",
			},
			want: true,
		},
		{
			name: "with http and https proxy",
			proxyConfig: &httpproxy.Config{
				HTTPProxy:  "proxy-url",
				HTTPSProxy: "proxy-url",
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isProxyConfigured(tt.proxyConfig); got != tt.want {
				t.Errorf("isProxyConfigured() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_proxyFunc(t *testing.T) {
	httpsProxy := "https://test.com:443"
	httpsProxyURL, err := url.Parse(httpsProxy)
	if err != nil {
		t.Fatal(err)
	}

	httpProxy := "test.com:80"
	httpProxyURL, err := url.Parse(httpProxy)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		httpsProxy string
		httpProxy  string
		req        *http.Request
		want       *url.URL
		wantErr    bool
	}{
		{
			name:       "valid https proxy with https url scheme",
			httpsProxy: httpsProxy,
			req: &http.Request{
				URL: httpsProxyURL,
			},
			want: httpsProxyURL,
		},
		{
			name:      "valid http proxy with http url scheme",
			httpProxy: httpProxy,
			req: &http.Request{
				URL: httpProxyURL,
			},
			want: httpProxyURL,
		},
		{
			name:      "valid http proxy with https url scheme",
			httpProxy: httpProxy,
			req: &http.Request{
				URL: httpsProxyURL,
			},
			want: httpProxyURL,
		},
		{
			name:       "invalid https proxy but valid http proxy",
			httpsProxy: "this-url-is-invalid%1^",
			httpProxy:  httpProxy,
			req: &http.Request{
				URL: httpsProxyURL,
			},
			want: httpProxyURL,
		},
		{
			name:       "invalid https proxy and invalid http proxy",
			httpsProxy: "this-url-is-invalid%1^",
			httpProxy:  "this-url-is-invalid%1^",
			req: &http.Request{
				URL: httpsProxyURL,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := os.Setenv("HTTPS_PROXY", tt.httpsProxy); err != nil {
				t.Error(err)
				return
			}

			if err := os.Setenv("HTTP_PROXY", tt.httpProxy); err != nil {
				t.Error(err)
				return
			}

			got, err := proxyFunc(tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("proxyFunc() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("proxyFunc() got = %v, want %v", got, tt.want)
			}

			if err := os.Unsetenv("HTTPS_PROXY"); err != nil {
				t.Error(err)
				return
			}
			if err := os.Unsetenv("HTTP_PROXY"); err != nil {
				t.Error(err)
				return
			}
		})
	}
}

func Test_checkProxyConfig(t *testing.T) {
	endpoint := "https://proxy.testing.com:443"
	endpointURL, err := url.Parse(endpoint)
	if err != nil {
		t.Fatal(err)
	}

	goodHTTPClient := &http.Client{
		Transport: &workingHTTPRoundTripper{},
	}
	badHTTPClient := &http.Client{
		Transport: &faultyHTTPRoundTripper{},
	}
	tests := []struct {
		name               string
		noProxy            string
		clientWithProxy    *http.Client
		clientWithoutProxy *http.Client
		wantErr            error
	}{
		{
			name:               "good proxy config with endpoint not matching noProxy",
			clientWithProxy:    goodHTTPClient,
			clientWithoutProxy: badHTTPClient,
		},
		{
			name:               "good proxy config with endpoint matching noProxy",
			noProxy:            "proxy.testing.com",
			clientWithProxy:    badHTTPClient,
			clientWithoutProxy: goodHTTPClient,
		},
		{
			name:               "good proxy config with endpoint matching domain in noProxy",
			noProxy:            "testing.com",
			clientWithProxy:    badHTTPClient,
			clientWithoutProxy: goodHTTPClient,
		},
		{
			name:               "endpoint matching noProxy is unreachable with/without proxy",
			noProxy:            "testing.com",
			clientWithProxy:    badHTTPClient,
			clientWithoutProxy: badHTTPClient,
			wantErr:            fmt.Errorf("endpoint(%q) found in NO_PROXY(%q) is unreachable with proxy(%q returned 404) and without proxy(%q returned 404)", endpoint, "testing.com", endpoint, endpoint),
		},
		{
			name:               "endpoint matching noProxy is reachable with proxy",
			noProxy:            "proxy.testing.com",
			clientWithProxy:    goodHTTPClient,
			clientWithoutProxy: badHTTPClient,
			wantErr:            fmt.Errorf("failed to reach endpoint(%q) found in NO_PROXY(%q) with error: %q returned 404", endpoint, "proxy.testing.com", endpoint),
		},
		{
			name:               "endpoint not matching noProxy is reachable without proxy",
			clientWithProxy:    badHTTPClient,
			clientWithoutProxy: goodHTTPClient,
			wantErr:            fmt.Errorf("failed to reach endpoint(%q) missing in NO_PROXY(\"\") with error: %q returned 404", endpoint, endpoint),
		},
		{
			name:               "endpoint not matching noProxy is unreachable with/without proxy",
			clientWithProxy:    badHTTPClient,
			clientWithoutProxy: badHTTPClient,
			wantErr:            fmt.Errorf("endpoint(%q) is unreachable with proxy(%q returned 404) and without proxy(%q returned 404)", endpoint, endpoint, endpoint),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkProxyConfig(context.TODO(), endpointURL, tt.noProxy, tt.clientWithProxy, tt.clientWithoutProxy)
			if !reflect.DeepEqual(err, tt.wantErr) {
				t.Errorf("checkProxyConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

type workingHTTPRoundTripper struct{}
type faultyHTTPRoundTripper struct{}

func (s *workingHTTPRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
}

func (s *faultyHTTPRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 404, Body: http.NoBody}, nil
}
