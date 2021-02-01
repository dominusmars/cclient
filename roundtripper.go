package cclient

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"strconv"
	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"

	utls "gitlab.com/dominusmars/utls.git"
)

var errProtocolNegotiated = errors.New("protocol negotiated")

type roundTripper struct {
	sync.Mutex

	clientHelloId     utls.ClientHelloID
	ja3 string
	cachedConnections map[string]net.Conn
	cachedTransports  map[string]http.RoundTripper

	dialer proxy.ContextDialer
}

//GetSpecFromJa3 returns ClientHelloSpec from ja3.json  To change utls fingerprint change this function 
func GetSpecFromJa3(s string) (*utls.ClientHelloSpec, error) {
	var err error
	tlsSpec := strings.Split(s, ",")

	//breaks ciphers from ja3
	ciphers := strings.Split(tlsSpec[1], "-")
	var ciphersFormated []uint16
	ciphersFormated = append(ciphersFormated, utls.GREASE_PLACEHOLDER)
	for i := range ciphers{
		j, err := formatToUint16(ciphers[i])
		if err != nil {
		   return nil, fmt.Errorf("ciphersFormated error: %+v", err)
		}
		ciphersFormated = append(ciphersFormated,j)
   }

    //gets ellipticsCurves from ja3
    ellipticCurves := strings.Split(tlsSpec[3], "-")
	ellipticFormated := []utls.CurveID{}
	for i := range ellipticCurves{
		j, err := formatToUint16(ellipticCurves[i])
		if err != nil {
		   return nil, fmt.Errorf("ellipticFormated error: %+v", err)
		}
		ellipticFormated = append(ellipticFormated, utls.CurveID(j))
   }

   //get curvePoint from ja3
   curvePoint := strings.Split(tlsSpec[4], "-")
   curvePointFormated := []byte{}
   
   for i := range curvePoint{
	
	j, err := formatToUint16(curvePoint[i])
	if err != nil {
		return nil, fmt.Errorf("curvePointFormated error: %+v", err)
	}
	curvePointFormated = append(curvePointFormated,byte(j))
	}

	return  &utls.ClientHelloSpec{
		TLSVersMax: utls.VersionTLS13,
		TLSVersMin: utls.VersionTLS10,
		CipherSuites: ciphersFormated,
		CompressionMethods: []uint8{},
		Extensions:
		[]utls.TLSExtension{
			&utls.UtlsGREASEExtension{Body: []byte{}},
			&utls.SNIExtension{},
			&utls.UtlsExtendedMasterSecretExtension{},
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
			&utls.SupportedCurvesExtension{Curves: ellipticFormated},
			&utls.SupportedPointsExtension{SupportedPoints: curvePointFormated},
			&utls.SessionTicketExtension{},
			&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			&utls.StatusRequestExtension{},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				0x0403,
				0x0804,
				0x0401,
				0x0503,
				0x0805,
				0x0501,
				0x0806,
				0x0601,
						}},	
						&utls.SCTExtension{},		
				&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.CurveID(utls.GREASE_PLACEHOLDER), Data: []byte{0}},
				{Group: utls.X25519},
			}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
			&utls.SupportedVersionsExtension{Versions: []uint16{
				utls.GREASE_PLACEHOLDER,
				0x0304,
				0x0303,
				0x0302,
				0x0301,
				}},
			&utls.CompressCertificateExtension{Algorithms: []utls.CertCompressionAlgo{
				utls.CertCompressionBrotli,
			}},
			&utls.UtlsGREASEExtension{Body: []byte{0}},
			&utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle},
		},
		GetSessionID: nil,

	}, err
}
//formatToUint16 is a helper function for GetSpecFromJa3
func formatToUint16(s string) (uint16, error) {
	integer, err := strconv.Atoi(s)
	if err != nil{
		return 0, err
	}
	return uint16(integer), err
}
func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	addr := rt.getDialTLSAddr(req)
	if _, ok := rt.cachedTransports[addr]; !ok {
		if err := rt.getTransport(req, addr); err != nil {
			return nil, err
		}
	}
	return rt.cachedTransports[addr].RoundTrip(req)
}

func (rt *roundTripper) getTransport(req *http.Request, addr string) error {
	switch strings.ToLower(req.URL.Scheme) {
	case "http":
		rt.cachedTransports[addr] = &http.Transport{DialContext: rt.dialer.DialContext}
		return nil
	case "https":
	default:
		return fmt.Errorf("invalid URL scheme: [%v]", req.URL.Scheme)
	}

	_, err := rt.dialTLS(context.Background(), "tcp", addr)
	switch err {
	case errProtocolNegotiated:
	case nil:
		// Should never happen.
		panic("dialTLS returned no error when determining cachedTransports")
	default:
		return err
	}

	return nil
}

func (rt *roundTripper) dialTLS(ctx context.Context, network, addr string) (net.Conn, error) {
	rt.Lock()
	defer rt.Unlock()

	// If we have the connection from when we determined the HTTPS
	// cachedTransports to use, return that.
	if conn := rt.cachedConnections[addr]; conn != nil {
		delete(rt.cachedConnections, addr)
		return conn, nil
	}

	rawConn, err := rt.dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	var host string
	if host, _, err = net.SplitHostPort(addr); err != nil {
		host = addr
	}

	conn := utls.UClient(rawConn, &utls.Config{ServerName: host}, rt.clientHelloId)
	if rt.ja3 != ""{
		spec, err := GetSpecFromJa3(rt.ja3)
		if err != nil {
			return nil, err
		}
		conn.ApplyPreset(spec)
	}

	if err = conn.Handshake(); err != nil {
		_ = conn.Close()
		return nil, err
	}

	if rt.cachedTransports[addr] != nil {
		return conn, nil
	}

	// No http.Transport constructed yet, create one based on the results
	// of ALPN.
	switch conn.ConnectionState().NegotiatedProtocol {
	case http2.NextProtoTLS:
		// The remote peer is speaking HTTP 2 + TLS.
		rt.cachedTransports[addr] = &http2.Transport{DialTLS: rt.dialTLSHTTP2}
	default:
		// Assume the remote peer is speaking HTTP 1.x + TLS.
		rt.cachedTransports[addr] = &http.Transport{DialTLSContext: rt.dialTLS}
	}

	// Stash the connection just established for use servicing the
	// actual request (should be near-immediate).
	rt.cachedConnections[addr] = conn

	return nil, errProtocolNegotiated
}

func (rt *roundTripper) dialTLSHTTP2(network, addr string, _ *tls.Config) (net.Conn, error) {
	return rt.dialTLS(context.Background(), network, addr)
}

func (rt *roundTripper) getDialTLSAddr(req *http.Request) string {
	host, port, err := net.SplitHostPort(req.URL.Host)
	if err == nil {
		return net.JoinHostPort(host, port)
	}
	return net.JoinHostPort(req.URL.Host, "443") // we can assume port is 443 at this point
}

func newRoundTripper(ja3 string, clientHello utls.ClientHelloID, dialer ...proxy.ContextDialer) http.RoundTripper {
	if len(dialer) > 0 {
		return &roundTripper{
			dialer: dialer[0],

			clientHelloId: clientHello,
			ja3: ja3,
			cachedTransports:  make(map[string]http.RoundTripper),
			cachedConnections: make(map[string]net.Conn),
		}
	} else {
		return &roundTripper{
			dialer: proxy.Direct,

			clientHelloId: clientHello,
			ja3: ja3,
			cachedTransports:  make(map[string]http.RoundTripper),
			cachedConnections: make(map[string]net.Conn),
		}
	}
}
