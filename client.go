package cclient

import (
	"golang.org/x/net/proxy"
	"net/http"

	utls "gitlab.com/dominusmars/utls.git"
)
//NewClient Creates a new http client with the presets. FOR NO JA3 just preset use "" instead
func NewClient(ja3 string, clientHello utls.ClientHelloID, proxyUrl ...string) (http.Client, error) {
	if len(proxyUrl) > 0 && len(proxyUrl) > 0 {
		dialer, err := newConnectDialer(proxyUrl[0])
		if err != nil {
			return http.Client{}, err
		}
		return http.Client{
			Transport: newRoundTripper(ja3, clientHello, dialer),
		}, nil
	} else {
		return http.Client{
			Transport: newRoundTripper(ja3, clientHello, proxy.Direct),
		}, nil
	}
}
