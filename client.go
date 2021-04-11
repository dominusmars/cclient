package cclient

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"golang.org/x/net/proxy"

	utls "gitlab.com/dominusmars/utls.git"
)

//NewClient Creates a new http client with the presets. FOR NO JA3 just preset use "" instead
func NewClient(clientHello utls.ClientHelloID,UserAgent string, proxyUrl ...string) (http.Client, error) {
	if len(proxyUrl) > 0 {
		dialer, err := newConnectDialer(proxyUrl[0] , UserAgent)
		if err != nil {
			return http.Client{}, err
		}
		return http.Client{
			Transport: newRoundTripper(clientHello, dialer),
		}, nil
	} else {
		return http.Client{
			Transport: newRoundTripper(clientHello, proxy.Direct),
		}, nil
	}
}
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