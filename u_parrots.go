// Copyright 2017 Google Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"sort"
	"strconv"
)

// UTLSIdToSpec converts a ClientHelloID to a corresponding ClientHelloSpec.
//
// Exported internal function utlsIdToSpec per request.
func UTLSIdToSpec(id ClientHelloID) (ClientHelloSpec, error) {
	return utlsIdToSpec(id)
}

func utlsIdToSpec(id ClientHelloID) (ClientHelloSpec, error) {
	switch id.Str() {
	case HelloChrome_58.Str(), HelloChrome_62.Str():
		return ClientHelloSpec{
			TLSVersMax: VersionTLS12,
			TLSVersMin: VersionTLS10,
			CipherSuites: []uint16{
				GREASE_PLACEHOLDER,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			},
			CompressionMethods: []byte{CompressionNone},
			Extensions: []TLSExtension{
				&UtlsGREASEExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SNIExtension{},
				&UtlsExtendedMasterSecretExtension{},
				&SessionTicketExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
					PKCS1WithSHA1},
				},
				&StatusRequestExtension{},
				&SCTExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&FakeChannelIDExtension{},
				&SupportedPointsExtension{SupportedPoints: []byte{PointFormatUncompressed}},
				&SupportedCurvesExtension{[]CurveID{CurveID(GREASE_PLACEHOLDER),
					X25519, CurveP256, CurveP384}},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
			},
			GetSessionID: sha256.Sum256,
		}, nil
	case HelloChrome_70.Str():
		return ClientHelloSpec{
			TLSVersMin: VersionTLS10,
			TLSVersMax: VersionTLS13,
			CipherSuites: []uint16{
				GREASE_PLACEHOLDER,
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			},
			CompressionMethods: []byte{
				CompressionNone,
			},
			Extensions: []TLSExtension{
				&UtlsGREASEExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SNIExtension{},
				&UtlsExtendedMasterSecretExtension{},
				&SessionTicketExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
					PKCS1WithSHA1,
				}},
				&StatusRequestExtension{},
				&SCTExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&FakeChannelIDExtension{},
				&SupportedPointsExtension{SupportedPoints: []byte{
					PointFormatUncompressed,
				}},
				&KeyShareExtension{[]KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{[]uint8{pskModeDHE}},
				&SupportedVersionsExtension{[]uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
					VersionTLS12,
					VersionTLS11,
					VersionTLS10}},
				&SupportedCurvesExtension{[]CurveID{
					CurveID(GREASE_PLACEHOLDER),
					X25519,
					CurveP256,
					CurveP384,
				}},
				&UtlsCompressCertExtension{[]CertCompressionAlgo{CertCompressionBrotli}},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
			},
		}, nil
	case HelloChrome_72.Str():
		return ClientHelloSpec{
			CipherSuites: []uint16{
				GREASE_PLACEHOLDER,
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			},
			CompressionMethods: []byte{
				CompressionNone,
			},
			Extensions: []TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&UtlsExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{[]CurveID{
					CurveID(GREASE_PLACEHOLDER),
					X25519,
					CurveP256,
					CurveP384,
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{
					PointFormatUncompressed,
				}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
					PKCS1WithSHA1,
				}},
				&SCTExtension{},
				&KeyShareExtension{[]KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{[]uint8{
					PskModeDHE,
				}},
				&SupportedVersionsExtension{[]uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
					VersionTLS12,
					VersionTLS11,
					VersionTLS10,
				}},
				&UtlsCompressCertExtension{[]CertCompressionAlgo{
					CertCompressionBrotli,
				}},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
			},
		}, nil
	case HelloChrome_83.Str():
		return ClientHelloSpec{
			CipherSuites: []uint16{
				GREASE_PLACEHOLDER,
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethods: []byte{
				CompressionNone,
			},
			Extensions: []TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&UtlsExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{[]CurveID{
					CurveID(GREASE_PLACEHOLDER),
					X25519,
					CurveP256,
					CurveP384,
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{
					PointFormatUncompressed,
				}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
				}},
				&SCTExtension{},
				&KeyShareExtension{[]KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{[]uint8{
					PskModeDHE,
				}},
				&SupportedVersionsExtension{[]uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
					VersionTLS12,
					VersionTLS11,
					VersionTLS10,
				}},
				&UtlsCompressCertExtension{[]CertCompressionAlgo{
					CertCompressionBrotli,
				}},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
			},
		}, nil
	case HelloChrome_87.Str():
		return ClientHelloSpec{
			CipherSuites: []uint16{
				GREASE_PLACEHOLDER,
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethods: []byte{
				CompressionNone,
			},
			Extensions: []TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&UtlsExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{[]CurveID{
					CurveID(GREASE_PLACEHOLDER),
					X25519,
					CurveP256,
					CurveP384,
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{
					PointFormatUncompressed,
				}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
				}},
				&SCTExtension{},
				&KeyShareExtension{[]KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{[]uint8{
					PskModeDHE,
				}},
				&SupportedVersionsExtension{[]uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
					VersionTLS12,
					VersionTLS11,
					VersionTLS10,
				}},
				&UtlsCompressCertExtension{[]CertCompressionAlgo{
					CertCompressionBrotli,
				}},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
			},
		}, nil
	case HelloChrome_96.Str():
		return ClientHelloSpec{
			CipherSuites: []uint16{
				GREASE_PLACEHOLDER,
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethods: []byte{
				CompressionNone,
			},
			Extensions: []TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&UtlsExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{[]CurveID{
					CurveID(GREASE_PLACEHOLDER),
					X25519,
					CurveP256,
					CurveP384,
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{
					PointFormatUncompressed,
				}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
				}},
				&SCTExtension{},
				&KeyShareExtension{[]KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{[]uint8{
					PskModeDHE,
				}},
				&SupportedVersionsExtension{[]uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
					VersionTLS12,
					VersionTLS11,
					VersionTLS10,
				}},
				&UtlsCompressCertExtension{[]CertCompressionAlgo{
					CertCompressionBrotli,
				}},
				&ALPNExtension{AlpnProtocols: []string{"h2"}},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
			},
		}, nil
	case HelloChrome_100.Str(),HelloChrome_102:
		return ClientHelloSpec{
			CipherSuites: []uint16{
				GREASE_PLACEHOLDER,
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethods: []uint8{
				CompressionNone,
			},
			Extensions: []TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&UtlsExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{[]CurveID{
					CurveID(GREASE_PLACEHOLDER),
					X25519,
					CurveP256,
					CurveP384,
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{
					PointFormatUncompressed,
				}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
				}},
				&SCTExtension{},
				&KeyShareExtension{[]KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{[]uint8{
					PskModeDHE,
				}},
				&SupportedVersionsExtension{[]uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
					VersionTLS12,
				}},
				&UtlsCompressCertExtension{[]CertCompressionAlgo{
					CertCompressionBrotli,
				}},
				&ALPSExtension{SupportedProtocols: []string{"h2"}},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
			},
		}, nil
	case HelloChrome_103.Str(), HelloChrome_104.Str(), HelloChrome_105.Str(), HelloChrome_106.Str():
		return ClientHelloSpec{
			CipherSuites: []uint16{
				GREASE_PLACEHOLDER,
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethods: []uint8{
				CompressionNone,
			},
			Extensions: []TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&UtlsExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{[]CurveID{
					CurveID(GREASE_PLACEHOLDER),
					X25519,
					CurveP256,
					CurveP384,
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{
					PointFormatUncompressed,
				}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
				}},
				&SCTExtension{},
				&KeyShareExtension{[]KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{[]uint8{
					PskModeDHE,
				}},
				&SupportedVersionsExtension{[]uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
					VersionTLS12,
				}},
				&UtlsCompressCertExtension{[]CertCompressionAlgo{
					CertCompressionBrotli,
				}},
				&ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
			},
		}, nil
	case HelloChrome_100_PSK:
		return ClientHelloSpec{
			CipherSuites: []uint16{
				GREASE_PLACEHOLDER,
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethods: []byte{
				0x00, // compressionNone
			},
			Extensions: []TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&UtlsExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{[]CurveID{
					GREASE_PLACEHOLDER,
					X25519,
					CurveP256,
					CurveP384,
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{
					0x00, // pointFormatUncompressed
				}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
				}},
				&SCTExtension{},
				&KeyShareExtension{[]KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{[]uint8{
					PskModeDHE,
				}},
				&SupportedVersionsExtension{[]uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
					VersionTLS12,
				}},
				&UtlsCompressCertExtension{[]CertCompressionAlgo{
					CertCompressionBrotli,
				}},
				&ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}},
				&UtlsGREASEExtension{},
				&FakePreSharedKeyExtension{},
			},
		}, nil
	case HelloChrome_106_Shuffle:
		chs, err := utlsIdToSpec(HelloChrome_102)
		if err != nil {
			return chs, err
		}

		// Chrome 107 started shuffling the order of extensions
		shuffleExtensions(&chs)
		return chs, err
	case HelloChrome_112_PSK_Shuf:
		chs, err := utlsIdToSpec(HelloChrome_100_PSK)
		if err != nil {
			return chs, err
		}

		// Chrome 112 started shuffling the order of extensions
		shuffleExtensions(&chs)
		return chs, err
	case HelloFirefox_55.Str(), HelloFirefox_56.Str():
		return ClientHelloSpec{
			TLSVersMax: VersionTLS12,
			TLSVersMin: VersionTLS10,
			CipherSuites: []uint16{
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				FAKE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
				FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			},
			CompressionMethods: []byte{CompressionNone},
			Extensions: []TLSExtension{
				&SNIExtension{},
				&UtlsExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{[]CurveID{X25519, CurveP256, CurveP384, CurveP521}},
				&SupportedPointsExtension{SupportedPoints: []byte{PointFormatUncompressed}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					ECDSAWithP384AndSHA384,
					ECDSAWithP521AndSHA512,
					PSSWithSHA256,
					PSSWithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA256,
					PKCS1WithSHA384,
					PKCS1WithSHA512,
					ECDSAWithSHA1,
					PKCS1WithSHA1},
				},
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
			},
			GetSessionID: nil,
		}, nil
	case HelloFirefox_63.Str(), HelloFirefox_65.Str():
		return ClientHelloSpec{
			TLSVersMin: VersionTLS10,
			TLSVersMax: VersionTLS13,
			CipherSuites: []uint16{
				TLS_AES_128_GCM_SHA256,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				FAKE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
				FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			},
			CompressionMethods: []byte{
				CompressionNone,
			},
			Extensions: []TLSExtension{
				&SNIExtension{},
				&UtlsExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{[]CurveID{
					X25519,
					CurveP256,
					CurveP384,
					CurveP521,
					CurveID(FakeFFDHE2048),
					CurveID(FakeFFDHE3072),
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{
					PointFormatUncompressed,
				}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&KeyShareExtension{[]KeyShare{
					{Group: X25519},
					{Group: CurveP256},
				}},
				&SupportedVersionsExtension{[]uint16{
					VersionTLS13,
					VersionTLS12,
					VersionTLS11,
					VersionTLS10}},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					ECDSAWithP384AndSHA384,
					ECDSAWithP521AndSHA512,
					PSSWithSHA256,
					PSSWithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA256,
					PKCS1WithSHA384,
					PKCS1WithSHA512,
					ECDSAWithSHA1,
					PKCS1WithSHA1,
				}},
				&PSKKeyExchangeModesExtension{[]uint8{pskModeDHE}},
				&FakeRecordSizeLimitExtension{0x4001},
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
			}}, nil
	case HelloFirefox_102.Str(), HelloFirefox_104.Str(), HelloFirefox_105.Str():
		return ClientHelloSpec{
			CipherSuites: []uint16{
				TLS_AES_128_GCM_SHA256,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethods: []byte{
				CompressionNone,
			},
			Extensions: []TLSExtension{
				&SNIExtension{},
				&UtlsExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{[]CurveID{
					X25519,
					CurveP256,
					CurveP384,
					CurveP521,
					CurveID(FakeFFDHE2048),
					CurveID(FakeFFDHE3072),
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{
					PointFormatUncompressed,
				}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				// &GenericExtension{Id: ExtensionDelegatedCredentials},
				&DelegatedCredentialsExtension{
					AlgorithmsSignature: []SignatureScheme{
						ECDSAWithP256AndSHA256,
						ECDSAWithP384AndSHA384,
						ECDSAWithP521AndSHA512,
						ECDSAWithSHA1,
					},
				},
				&KeyShareExtension{[]KeyShare{
					{Group: X25519},
					{Group: CurveP256},
				}},
				&SupportedVersionsExtension{[]uint16{
					VersionTLS13,
					VersionTLS12,
				}},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					ECDSAWithP384AndSHA384,
					ECDSAWithP521AndSHA512,
					PSSWithSHA256,
					PSSWithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA256,
					PKCS1WithSHA384,
					PKCS1WithSHA512,
					ECDSAWithSHA1,
					PKCS1WithSHA1,
				}},
				&PSKKeyExchangeModesExtension{[]uint8{pskModeDHE}},
				&FakeRecordSizeLimitExtension{0x4001},
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
			}}, nil
	case HelloOpera_89.Str(), HelloOpera_90.Str(), HelloOpera_91.Str():
		return ClientHelloSpec{
			CipherSuites: []uint16{
				GREASE_PLACEHOLDER,
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethods: []uint8{
				0x00,
			},
			Extensions: []TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&UtlsExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient}, // ExtensionRenegotiationInfo (boringssl) (65281)
				&SupportedCurvesExtension{[]CurveID{
					CurveID(GREASE_PLACEHOLDER),
					X25519,
					CurveP256,
					CurveP384,
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{
					0x00, // PointFormatUncompressed
				}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
				}},
				&SCTExtension{},
				&KeyShareExtension{[]KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{[]uint8{
					PskModeDHE,
				}},
				&SupportedVersionsExtension{[]uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
					VersionTLS12,
				}},
				&UtlsCompressCertExtension{[]CertCompressionAlgo{
					CertCompressionBrotli,
				}},
				&ALPSExtension{SupportedProtocols: []string{"h2"}},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
			}}, nil
	case HelloChrome_102.Str():
		return ClientHelloSpec{
			CipherSuites: []uint16{
				GREASE_PLACEHOLDER,
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethods: []byte{
				0x00, // compressionNone
			},
			Extensions: []TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&UtlsExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{[]CurveID{
					GREASE_PLACEHOLDER,
					X25519,
					CurveP256,
					CurveP384,
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{
					PointFormatUncompressed,
				}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
				}},
				&SCTExtension{},
				&KeyShareExtension{[]KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{[]uint8{
					PskModeDHE,
				}},
				&SupportedVersionsExtension{[]uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
					VersionTLS12,
				}},
				&UtlsCompressCertExtension{[]CertCompressionAlgo{
					CertCompressionBrotli,
				}},
				&ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
			},
		}, nil

	case HelloFirefox_99.Str():
		return ClientHelloSpec{
			TLSVersMin: VersionTLS10,
			TLSVersMax: VersionTLS13,
			CipherSuites: []uint16{
				TLS_AES_128_GCM_SHA256,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			},
			CompressionMethods: []byte{
				CompressionNone,
			},
			Extensions: []TLSExtension{
				&SNIExtension{},                      //server_name
				&UtlsExtendedMasterSecretExtension{}, //extended_master_secret
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient}, //extensionRenegotiationInfo
				&SupportedCurvesExtension{[]CurveID{ //supported_groups
					X25519,
					CurveP256,
					CurveP384,
					CurveP521,
					CurveID(FakeFFDHE2048),
					CurveID(FakeFFDHE3072),
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{ //ec_point_formats
					PointFormatUncompressed,
				}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}}, //application_layer_protocol_negotiation
				&StatusRequestExtension{},
				&FakeDelegatedCredentialsExtension{
					SupportedSignatureAlgorithms: []SignatureScheme{ //signature_algorithms
						ECDSAWithP256AndSHA256,
						ECDSAWithP384AndSHA384,
						ECDSAWithP521AndSHA512,
						ECDSAWithSHA1,
					},
				},
				&KeyShareExtension{[]KeyShare{
					{Group: X25519},
					{Group: CurveP256}, //key_share
				}},
				&SupportedVersionsExtension{[]uint16{
					VersionTLS13, //supported_versions
					VersionTLS12,
					VersionTLS11,
					VersionTLS10,
				}},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{ //signature_algorithms
					ECDSAWithP256AndSHA256,
					ECDSAWithP384AndSHA384,
					ECDSAWithP521AndSHA512,
					PSSWithSHA256,
					PSSWithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA256,
					PKCS1WithSHA384,
					PKCS1WithSHA512,
					ECDSAWithSHA1,
					PKCS1WithSHA1,
				}},
				&PSKKeyExchangeModesExtension{[]uint8{ //psk_key_exchange_modes
					PskModeDHE,
				}},
				&FakeRecordSizeLimitExtension{Limit: 0x4001},             //record_size_limit
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle}, //padding
			}}, nil
	case HelloFirefox_102:
		return ClientHelloSpec{
			TLSVersMin: VersionTLS10,
			TLSVersMax: VersionTLS13,
			CipherSuites: []uint16{
				TLS_AES_128_GCM_SHA256,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethods: []byte{
				compressionNone,
			},
			Extensions: []TLSExtension{
				&SNIExtension{},                      //server_name
				&UtlsExtendedMasterSecretExtension{}, //extended_master_secret
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient}, //extensionRenegotiationInfo
				&SupportedCurvesExtension{[]CurveID{ //supported_groups
					X25519,
					CurveP256,
					CurveP384,
					CurveP521,
					CurveID(FakeFFDHE2048),
					CurveID(FakeFFDHE3072),
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{ //ec_point_formats
					pointFormatUncompressed,
				}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2"}}, //application_layer_protocol_negotiation
				&StatusRequestExtension{},
				&FakeDelegatedCredentialsExtension{
					SupportedSignatureAlgorithms: []SignatureScheme{ //signature_algorithms
						ECDSAWithP256AndSHA256,
						ECDSAWithP384AndSHA384,
						ECDSAWithP521AndSHA512,
						ECDSAWithSHA1,
					},
				},
				&KeyShareExtension{[]KeyShare{
					{Group: X25519},
					{Group: CurveP256}, //key_share
				}},
				&SupportedVersionsExtension{[]uint16{
					VersionTLS13, //supported_versions
					VersionTLS12,
				}},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{ //signature_algorithms
					ECDSAWithP256AndSHA256,
					ECDSAWithP384AndSHA384,
					ECDSAWithP521AndSHA512,
					PSSWithSHA256,
					PSSWithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA256,
					PKCS1WithSHA384,
					PKCS1WithSHA512,
					ECDSAWithSHA1,
					PKCS1WithSHA1,
				}},
				&PSKKeyExchangeModesExtension{[]uint8{ //psk_key_exchange_modes
					PskModeDHE,
				}},
				&FakeRecordSizeLimitExtension{Limit: 0x4001},             //record_size_limit
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle}, //padding
			}}, nil
	case HelloFirefox_105:
		return ClientHelloSpec{
			TLSVersMin: VersionTLS12,
			TLSVersMax: VersionTLS13,
			CipherSuites: []uint16{
				TLS_AES_128_GCM_SHA256,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethods: []uint8{
				0x0, // no compression
			},
			Extensions: []TLSExtension{
				&SNIExtension{},
				&UtlsExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{
					Renegotiation: RenegotiateOnceAsClient,
				},
				&SupportedCurvesExtension{
					Curves: []CurveID{
						X25519,
						CurveP256,
						CurveP384,
						CurveP521,
						256,
						257,
					},
				},
				&SupportedPointsExtension{
					SupportedPoints: []uint8{
						0x0, // uncompressed
					},
				},
				&SessionTicketExtension{},
				&ALPNExtension{
					AlpnProtocols: []string{
						"h2",
						"http/1.1",
					},
				},
				&StatusRequestExtension{},
				&FakeDelegatedCredentialsExtension{
					SupportedSignatureAlgorithms: []SignatureScheme{
						ECDSAWithP256AndSHA256,
						ECDSAWithP384AndSHA384,
						ECDSAWithP521AndSHA512,
						ECDSAWithSHA1,
					},
				},
				&KeyShareExtension{
					KeyShares: []KeyShare{
						{
							Group: X25519,
						},
						{
							Group: CurveP256,
						},
					},
				},
				&SupportedVersionsExtension{
					Versions: []uint16{
						VersionTLS13,
						VersionTLS12,
					},
				},
				&SignatureAlgorithmsExtension{
					SupportedSignatureAlgorithms: []SignatureScheme{
						ECDSAWithP256AndSHA256,
						ECDSAWithP384AndSHA384,
						ECDSAWithP521AndSHA512,
						PSSWithSHA256,
						PSSWithSHA384,
						PSSWithSHA512,
						PKCS1WithSHA256,
						PKCS1WithSHA384,
						PKCS1WithSHA512,
						ECDSAWithSHA1,
						PKCS1WithSHA1,
					},
				},
				&PSKKeyExchangeModesExtension{
					Modes: []uint8{
						PskModeDHE,
					},
				},
				&FakeRecordSizeLimitExtension{
					Limit: 0x4001,
				},
				&UtlsPaddingExtension{
					GetPaddingLen: BoringPaddingStyle,
				},
			},
		}, nil
	case HelloIOS_11_1.Str():
		return ClientHelloSpec{
			TLSVersMax: VersionTLS12,
			TLSVersMin: VersionTLS10,
			CipherSuites: []uint16{
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				DISABLED_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
				TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				DISABLED_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256,
				TLS_RSA_WITH_AES_128_CBC_SHA256,
				TLS_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_CBC_SHA,
			},
			CompressionMethods: []byte{
				CompressionNone,
			},
			Extensions: []TLSExtension{
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SNIExtension{},
				&UtlsExtendedMasterSecretExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
					PKCS1WithSHA1,
				}},
				&StatusRequestExtension{},
				&NPNExtension{},
				&SCTExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "h2-16", "h2-15", "h2-14", "spdy/3.1", "spdy/3", "http/1.1"}},
				&SupportedPointsExtension{SupportedPoints: []byte{
					PointFormatUncompressed,
				}},
				&SupportedCurvesExtension{Curves: []CurveID{
					X25519,
					CurveP256,
					CurveP384,
					CurveP521,
				}},
			},
		}, nil
	case HelloIOS_12_1.Str():
		return ClientHelloSpec{
			CipherSuites: []uint16{
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				DISABLED_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
				TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				DISABLED_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256,
				TLS_RSA_WITH_AES_128_CBC_SHA256,
				TLS_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				0xc008,
				TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
				TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			},
			CompressionMethods: []byte{
				CompressionNone,
			},
			Extensions: []TLSExtension{
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SNIExtension{},
				&UtlsExtendedMasterSecretExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					ECDSAWithSHA1,
					PSSWithSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
					PKCS1WithSHA1,
				}},
				&StatusRequestExtension{},
				&NPNExtension{},
				&SCTExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "h2-16", "h2-15", "h2-14", "spdy/3.1", "spdy/3", "http/1.1"}},
				&SupportedPointsExtension{SupportedPoints: []byte{
					PointFormatUncompressed,
				}},
				&SupportedCurvesExtension{[]CurveID{
					X25519,
					CurveP256,
					CurveP384,
					CurveP521,
				}},
			},
		}, nil
	case HelloIOS_13.Str():
		return ClientHelloSpec{
			CipherSuites: []uint16{
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				DISABLED_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
				TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				DISABLED_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256,
				TLS_RSA_WITH_AES_128_CBC_SHA256,
				TLS_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				0xc008,
				TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
				TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			},
			CompressionMethods: []byte{
				CompressionNone,
			},
			Extensions: []TLSExtension{
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SNIExtension{},
				&UtlsExtendedMasterSecretExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					ECDSAWithSHA1,
					PSSWithSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
					PKCS1WithSHA1,
				}},
				&StatusRequestExtension{},
				&SCTExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&SupportedPointsExtension{SupportedPoints: []byte{
					PointFormatUncompressed,
				}},
				&KeyShareExtension{[]KeyShare{
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{[]uint8{
					PskModeDHE,
				}},
				&SupportedVersionsExtension{[]uint16{
					VersionTLS13,
					VersionTLS12,
					VersionTLS11,
					VersionTLS10,
				}},
				&SupportedCurvesExtension{[]CurveID{
					X25519,
					CurveP256,
					CurveP384,
					CurveP521,
				}},
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
			},
		}, nil
	case HelloIOS_14.Str():
		return ClientHelloSpec{
			// TLSVersMax: VersionTLS12,
			// TLSVersMin: VersionTLS10,
			CipherSuites: []uint16{
				GREASE_PLACEHOLDER,
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				DISABLED_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
				TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				DISABLED_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256,
				TLS_RSA_WITH_AES_128_CBC_SHA256,
				TLS_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				0xc008,
				TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
				TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			},
			CompressionMethods: []byte{
				CompressionNone,
			},
			Extensions: []TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&UtlsExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{[]CurveID{
					CurveID(GREASE_PLACEHOLDER),
					X25519,
					CurveP256,
					CurveP384,
					CurveP521,
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{
					PointFormatUncompressed,
				}},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					ECDSAWithSHA1,
					PSSWithSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
					PKCS1WithSHA1,
				}},
				&SCTExtension{},
				&KeyShareExtension{[]KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{[]uint8{
					PskModeDHE,
				}},
				&SupportedVersionsExtension{[]uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
					VersionTLS12,
					VersionTLS11,
					VersionTLS10,
				}},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
			},
		}, nil
	case HelloAndroid_11_OkHttp.Str():
		return ClientHelloSpec{
			CipherSuites: []uint16{
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				0xcca9, // Cipher Suite: TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca9)
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				0xcca8, // Cipher Suite: TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca8)
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethods: []byte{
				CompressionNone,
			},
			Extensions: []TLSExtension{
				&SNIExtension{},
				&UtlsExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{},
				// supported_groups
				&SupportedCurvesExtension{[]CurveID{
					X25519,
					CurveP256,
					CurveP384,
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{
					PointFormatUncompressed,
				}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
					PKCS1WithSHA1,
				}},
			},
		}, nil
	case HelloIOS_15_5.Str(), HelloIOS_15_6.Str(), HelloIPad_15_6.Str(), HelloIOS_16_0.Str():
		return ClientHelloSpec{
			CipherSuites: []uint16{
				GREASE_PLACEHOLDER,
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
				TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
				TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			},
			CompressionMethods: []byte{
				CompressionNone,
			},
			Extensions: []TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&UtlsExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{[]CurveID{
					CurveID(GREASE_PLACEHOLDER),
					X25519,
					CurveP256,
					CurveP384,
					CurveP521,
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{
					PointFormatUncompressed,
				}},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					ECDSAWithSHA1,
					PSSWithSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
					PKCS1WithSHA1,
				}},
				&SCTExtension{},
				&KeyShareExtension{[]KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{[]uint8{
					PskModeDHE,
				}},
				&SupportedVersionsExtension{[]uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
					VersionTLS12,
					VersionTLS11,
					VersionTLS10,
				}},
				&UtlsCompressCertExtension{[]CertCompressionAlgo{
					CertCompressionZlib,
				}},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
			},
		}, nil
	case HelloSafari_15_6_1.Str(), HelloSafari_16_0.Str():
		return ClientHelloSpec{
			CipherSuites: []uint16{
				GREASE_PLACEHOLDER,
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
				TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
				TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			},
			CompressionMethods: []byte{
				CompressionNone,
			},
			Extensions: []TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&UtlsExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{[]CurveID{
					CurveID(GREASE_PLACEHOLDER),
					X25519,
					CurveP256,
					CurveP384,
					CurveP521,
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{
					PointFormatUncompressed,
				}},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					ECDSAWithSHA1,
					PSSWithSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
					PKCS1WithSHA1,
				}},
				&SCTExtension{},
				&KeyShareExtension{[]KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{[]uint8{
					PskModeDHE,
				}},
				&SupportedVersionsExtension{[]uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
					VersionTLS12,
					VersionTLS11,
					VersionTLS10,
				}},
				&UtlsCompressCertExtension{[]CertCompressionAlgo{
					CertCompressionZlib,
				}},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
			},
		}, nil
	case HelloIOS_13:
		return ClientHelloSpec{
			CipherSuites: []uint16{
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				DISABLED_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
				TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				DISABLED_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256,
				TLS_RSA_WITH_AES_128_CBC_SHA256,
				TLS_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				0xc008,
				TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
				TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			},
			CompressionMethods: []byte{
				0x00, // compressionNone
			},
			Extensions: []TLSExtension{
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SNIExtension{},
				&UtlsExtendedMasterSecretExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					ECDSAWithSHA1,
					PSSWithSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
					PKCS1WithSHA1,
				}},
				&StatusRequestExtension{},
				&SCTExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&SupportedPointsExtension{SupportedPoints: []byte{
					0x00, // pointFormatUncompressed
				}},
				&KeyShareExtension{[]KeyShare{
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{[]uint8{
					PskModeDHE,
				}},
				&SupportedVersionsExtension{[]uint16{
					VersionTLS13,
					VersionTLS12,
					VersionTLS11,
					VersionTLS10,
				}},
				&SupportedCurvesExtension{[]CurveID{
					X25519,
					CurveP256,
					CurveP384,
					CurveP521,
				}},
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
			},
		}, nil
	case HelloIOS_14:
		return ClientHelloSpec{
			// TLSVersMax: VersionTLS12,
			// TLSVersMin: VersionTLS10,
			CipherSuites: []uint16{
				GREASE_PLACEHOLDER,
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				DISABLED_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
				TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				DISABLED_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256,
				TLS_RSA_WITH_AES_128_CBC_SHA256,
				TLS_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				0xc008,
				TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
				TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			},
			CompressionMethods: []byte{
				0x00, // compressionNone
			},
			Extensions: []TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&UtlsExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{[]CurveID{
					CurveID(GREASE_PLACEHOLDER),
					X25519,
					CurveP256,
					CurveP384,
					CurveP521,
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{
					0x00, // pointFormatUncompressed
				}},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					ECDSAWithSHA1,
					PSSWithSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
					PKCS1WithSHA1,
				}},
				&SCTExtension{},
				&KeyShareExtension{[]KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{[]uint8{
					PskModeDHE,
				}},
				&SupportedVersionsExtension{[]uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
					VersionTLS12,
					VersionTLS11,
					VersionTLS10,
				}},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
			},
		}, nil
	case HelloAndroid_11_OkHttp:
		return ClientHelloSpec{
			CipherSuites: []uint16{
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				0xcca9, // Cipher Suite: TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca9)
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				0xcca8, // Cipher Suite: TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca8)
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethods: []byte{
				0x00, // compressionNone
			},
			Extensions: []TLSExtension{
				&SNIExtension{},
				&UtlsExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{},
				// supported_groups
				&SupportedCurvesExtension{[]CurveID{
					X25519,
					CurveP256,
					CurveP384,
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{
					0x00, // pointFormatUncompressed
				}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
					PKCS1WithSHA1,
				}},
			},
		}, nil
	case HelloEdge_85:
		return ClientHelloSpec{
			CipherSuites: []uint16{
				GREASE_PLACEHOLDER,
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethods: []uint8{
				0x0, // no compression
			},
			Extensions: []TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&UtlsExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{
					Renegotiation: RenegotiateOnceAsClient,
				},
				&SupportedCurvesExtension{
					Curves: []CurveID{
						GREASE_PLACEHOLDER,
						X25519,
						CurveP256,
						CurveP384,
					},
				},
				&SupportedPointsExtension{
					SupportedPoints: []uint8{
						0x0, // pointFormatUncompressed
					},
				},
				&SessionTicketExtension{},
				&ALPNExtension{
					AlpnProtocols: []string{
						"h2",
						"http/1.1",
					},
				},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{
					SupportedSignatureAlgorithms: []SignatureScheme{
						ECDSAWithP256AndSHA256,
						PSSWithSHA256,
						PKCS1WithSHA256,
						ECDSAWithP384AndSHA384,
						PSSWithSHA384,
						PKCS1WithSHA384,
						PSSWithSHA512,
						PKCS1WithSHA512,
					},
				},
				&SCTExtension{},
				&KeyShareExtension{
					KeyShares: []KeyShare{
						{
							Group: GREASE_PLACEHOLDER,
							Data: []byte{
								0,
							},
						},
						{
							Group: X25519,
						},
					},
				},
				&PSKKeyExchangeModesExtension{
					Modes: []uint8{
						PskModeDHE,
					},
				},
				&SupportedVersionsExtension{
					Versions: []uint16{
						GREASE_PLACEHOLDER,
						VersionTLS13,
						VersionTLS12,
						VersionTLS11,
						VersionTLS10,
					},
				},
				&UtlsCompressCertExtension{
					Algorithms: []CertCompressionAlgo{
						CertCompressionBrotli,
					},
				},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{
					GetPaddingLen: BoringPaddingStyle,
				},
			},
		}, nil
	case HelloEdge_106:
		return ClientHelloSpec{
			TLSVersMin: VersionTLS12,
			TLSVersMax: VersionTLS13,
			CipherSuites: []uint16{
				GREASE_PLACEHOLDER,
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethods: []uint8{
				0x0, // no compression
			},
			Extensions: []TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&UtlsExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{
					Renegotiation: RenegotiateOnceAsClient,
				},
				&SupportedCurvesExtension{
					Curves: []CurveID{
						GREASE_PLACEHOLDER,
						X25519,
						CurveP256,
						CurveP384,
					},
				},
				&SupportedPointsExtension{
					SupportedPoints: []uint8{
						0x0, // uncompressed
					},
				},
				&SessionTicketExtension{},
				&ALPNExtension{
					AlpnProtocols: []string{
						"h2",
						"http/1.1",
					},
				},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{
					SupportedSignatureAlgorithms: []SignatureScheme{
						ECDSAWithP256AndSHA256,
						PSSWithSHA256,
						PKCS1WithSHA256,
						ECDSAWithP384AndSHA384,
						PSSWithSHA384,
						PKCS1WithSHA384,
						PSSWithSHA512,
						PKCS1WithSHA512,
					},
				},
				&SCTExtension{},
				&KeyShareExtension{
					KeyShares: []KeyShare{
						{
							Group: GREASE_PLACEHOLDER,
							Data: []byte{
								0,
							},
						},
						{
							Group: X25519,
						},
					},
				},
				&PSKKeyExchangeModesExtension{
					Modes: []uint8{
						PskModeDHE,
					},
				},
				&SupportedVersionsExtension{
					Versions: []uint16{
						GREASE_PLACEHOLDER,
						VersionTLS13,
						VersionTLS12,
					},
				},
				&UtlsCompressCertExtension{
					Algorithms: []CertCompressionAlgo{
						CertCompressionBrotli,
					},
				},
				&ApplicationSettingsExtension{
					SupportedProtocols: []string{
						"h2",
					},
				},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{
					GetPaddingLen: BoringPaddingStyle,
				},
			},
		}, nil
	case HelloSafari_16_0:
		return ClientHelloSpec{
			TLSVersMin: VersionTLS10,
			TLSVersMax: VersionTLS13,
			CipherSuites: []uint16{
				GREASE_PLACEHOLDER,
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				FAKE_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
				TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
				TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			},
			CompressionMethods: []uint8{
				0x0, // no compression
			},
			Extensions: []TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&UtlsExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{
					Renegotiation: RenegotiateOnceAsClient,
				},
				&SupportedCurvesExtension{
					Curves: []CurveID{
						GREASE_PLACEHOLDER,
						X25519,
						CurveP256,
						CurveP384,
						CurveP521,
					},
				},
				&SupportedPointsExtension{
					SupportedPoints: []uint8{
						0x0, // uncompressed
					},
				},
				&ALPNExtension{
					AlpnProtocols: []string{
						"h2",
						"http/1.1",
					},
				},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{
					SupportedSignatureAlgorithms: []SignatureScheme{
						ECDSAWithP256AndSHA256,
						PSSWithSHA256,
						PKCS1WithSHA256,
						ECDSAWithP384AndSHA384,
						ECDSAWithSHA1,
						PSSWithSHA384,
						PSSWithSHA384,
						PKCS1WithSHA384,
						PSSWithSHA512,
						PKCS1WithSHA512,
						PKCS1WithSHA1,
					},
				},
				&SCTExtension{},
				&KeyShareExtension{
					KeyShares: []KeyShare{
						{
							Group: GREASE_PLACEHOLDER,
							Data: []byte{
								0,
							},
						},
						{
							Group: X25519,
						},
					},
				},
				&PSKKeyExchangeModesExtension{
					Modes: []uint8{
						PskModeDHE,
					},
				},
				&SupportedVersionsExtension{
					Versions: []uint16{
						GREASE_PLACEHOLDER,
						VersionTLS13,
						VersionTLS12,
						VersionTLS11,
						VersionTLS10,
					},
				},
				&UtlsCompressCertExtension{
					Algorithms: []CertCompressionAlgo{
						CertCompressionZlib,
					},
				},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{
					GetPaddingLen: BoringPaddingStyle,
				},
			},
		}, nil
	case Hello360_7_5:
		return ClientHelloSpec{
			CipherSuites: []uint16{
				TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
				FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
				TLS_RSA_WITH_AES_256_CBC_SHA,
				DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256,
				TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
				TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
				TLS_ECDHE_RSA_WITH_RC4_128_SHA,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
				FAKE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
				FAKE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
				FAKE_TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_RC4_128_SHA,
				FAKE_TLS_RSA_WITH_RC4_128_MD5,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_128_CBC_SHA256,
				TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			},
			CompressionMethods: []uint8{
				0x0, // no compression
			},
			Extensions: []TLSExtension{
				&SNIExtension{},
				&RenegotiationInfoExtension{
					Renegotiation: RenegotiateOnceAsClient,
				},
				&SupportedCurvesExtension{
					Curves: []CurveID{
						CurveP256,
						CurveP384,
						CurveP521,
					},
				},
				&SupportedPointsExtension{
					SupportedPoints: []uint8{
						0x0, // pointFormatUncompressed
					},
				},
				&SessionTicketExtension{},
				&NPNExtension{},
				&ALPNExtension{
					AlpnProtocols: []string{
						"spdy/2",
						"spdy/3",
						"spdy/3.1",
						"http/1.1",
					},
				},
				&FakeChannelIDExtension{
					OldExtensionID: true,
				},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{
					SupportedSignatureAlgorithms: []SignatureScheme{
						PKCS1WithSHA256,
						PKCS1WithSHA384,
						PKCS1WithSHA1,
						ECDSAWithP256AndSHA256,
						ECDSAWithP384AndSHA384,
						ECDSAWithSHA1,
						FakeSHA256WithDSA,
						FakeSHA1WithDSA,
					},
				},
			},
		}, nil
	case Hello360_11_0:
		return ClientHelloSpec{
			TLSVersMin: VersionTLS10,
			TLSVersMax: VersionTLS13,
			CipherSuites: []uint16{
				GREASE_PLACEHOLDER,
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			},
			CompressionMethods: []uint8{
				0x0, // no compression
			},
			Extensions: []TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&UtlsExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{
					Renegotiation: RenegotiateOnceAsClient,
				},
				&SupportedCurvesExtension{
					Curves: []CurveID{
						GREASE_PLACEHOLDER,
						X25519,
						CurveP256,
						CurveP384,
					},
				},
				&SupportedPointsExtension{
					SupportedPoints: []uint8{
						0x0, // uncompressed
					},
				},
				&SessionTicketExtension{},
				&ALPNExtension{
					AlpnProtocols: []string{
						"h2",
						"http/1.1",
					},
				},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{
					SupportedSignatureAlgorithms: []SignatureScheme{
						ECDSAWithP256AndSHA256,
						PSSWithSHA256,
						PKCS1WithSHA256,
						ECDSAWithP384AndSHA384,
						PSSWithSHA384,
						PKCS1WithSHA384,
						PSSWithSHA512,
						PKCS1WithSHA512,
						PKCS1WithSHA1,
					},
				},
				&SCTExtension{},
				&FakeChannelIDExtension{
					OldExtensionID: false,
				},
				&KeyShareExtension{
					KeyShares: []KeyShare{
						{
							Group: GREASE_PLACEHOLDER,
							Data: []byte{
								0,
							},
						},
						{
							Group: X25519,
						},
					},
				},
				&PSKKeyExchangeModesExtension{
					Modes: []uint8{
						PskModeDHE,
					},
				},
				&SupportedVersionsExtension{
					Versions: []uint16{
						GREASE_PLACEHOLDER,
						VersionTLS13,
						VersionTLS12,
						VersionTLS11,
						VersionTLS10,
					},
				},
				&UtlsCompressCertExtension{
					Algorithms: []CertCompressionAlgo{
						CertCompressionBrotli,
					},
				},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{
					GetPaddingLen: BoringPaddingStyle,
				},
			},
		}, nil
	case HelloQQ_11_1:
		return ClientHelloSpec{
			TLSVersMin: VersionTLS10,
			TLSVersMax: VersionTLS13,
			CipherSuites: []uint16{
				GREASE_PLACEHOLDER,
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethods: []uint8{
				0x0, // no compression
			},
			Extensions: []TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&UtlsExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{
					Renegotiation: RenegotiateOnceAsClient,
				},
				&SupportedCurvesExtension{
					Curves: []CurveID{
						GREASE_PLACEHOLDER,
						X25519,
						CurveP256,
						CurveP384,
					},
				},
				&SupportedPointsExtension{
					SupportedPoints: []uint8{
						0x0, // uncompressed
					},
				},
				&SessionTicketExtension{},
				&ALPNExtension{
					AlpnProtocols: []string{
						"h2",
						"http/1.1",
					},
				},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{
					SupportedSignatureAlgorithms: []SignatureScheme{
						ECDSAWithP256AndSHA256,
						PSSWithSHA256,
						PKCS1WithSHA256,
						ECDSAWithP384AndSHA384,
						PSSWithSHA384,
						PKCS1WithSHA384,
						PSSWithSHA512,
						PKCS1WithSHA512,
					},
				},
				&SCTExtension{},
				&KeyShareExtension{
					KeyShares: []KeyShare{
						{
							Group: GREASE_PLACEHOLDER,
							Data: []byte{
								0,
							},
						},
						{
							Group: X25519,
						},
					},
				},
				&PSKKeyExchangeModesExtension{
					Modes: []uint8{
						PskModeDHE,
					},
				},
				&SupportedVersionsExtension{
					Versions: []uint16{
						GREASE_PLACEHOLDER,
						VersionTLS13,
						VersionTLS12,
						VersionTLS11,
						VersionTLS10,
					},
				},
				&UtlsCompressCertExtension{
					Algorithms: []CertCompressionAlgo{
						CertCompressionBrotli,
					},
				},
				&ApplicationSettingsExtension{
					SupportedProtocols: []string{
						"h2",
					},
				},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{
					GetPaddingLen: BoringPaddingStyle,
				},
			},
		}, nil
	default:
		if id.Client == helloRandomized || id.Client == helloRandomizedALPN || id.Client == helloRandomizedNoALPN {
			// Use empty values as they can be filled later by UConn.ApplyPreset or manually.
			return generateRandomizedSpec(&id, "", nil, nil)
		}
		return ClientHelloSpec{}, errors.New("ClientHello ID " + id.Str() + " is unknown")
	}
}

func shuffleExtensions(chs *ClientHelloSpec) error {
	// Shuffle extensions to avoid fingerprinting -- introduced in Chrome 106
	var err error = nil

	// unshufCheck checks:
	// - if the exts[idx] is a GREASE extension, then it should not be shuffled
	// - if the exts[idx] is a padding/pre_shared_key extension, then it should be the
	//  last extension in the list and should not be shuffled
	var unshufCheck = func(idx int, exts []TLSExtension) (donotshuf bool, userErr error) {
		switch exts[idx].(type) {
		case *UtlsGREASEExtension:
			donotshuf = true
		case *UtlsPaddingExtension, *FakePreSharedKeyExtension:
			donotshuf = true
			if idx != len(chs.Extensions)-1 {
				userErr = errors.New("UtlsPaddingExtension or FakePreSharedKeyExtension must be the last extension")
			}
		default:
			donotshuf = false
		}
		return
	}

	// Shuffle other extensions
	rand.Shuffle(len(chs.Extensions), func(i, j int) {
		if unshuf, shuferr := unshufCheck(i, chs.Extensions); unshuf {
			if shuferr != nil {
				err = shuferr
			}
			return
		}

		if unshuf, shuferr := unshufCheck(j, chs.Extensions); unshuf {
			if shuferr != nil {
				err = shuferr
			}
			return
		}

		chs.Extensions[i], chs.Extensions[j] = chs.Extensions[j], chs.Extensions[i]
	})

	return err
}

func (uconn *UConn) applyPresetByID(id ClientHelloID) (err error) {
	var spec ClientHelloSpec
	uconn.ClientHelloID = id
	// choose/generate the spec
	switch id.Client {
	case helloRandomized, helloRandomizedNoALPN, helloRandomizedALPN:
		spec, err = uconn.generateRandomizedSpec()
		if err != nil {
			return err
		}

		return uconn.ApplyPreset(&spec)
	case helloCustomInternal:
		return nil

	default:
		spec, err = utlsIdToSpec(id)
		if err != nil {
			providedSpec, err := id.ToSpec()
			if err != nil {
				return err
			}

			return uconn.ApplyPreset(&providedSpec)
		}

		return uconn.ApplyPreset(&spec)
	}
}

// ApplyPreset should only be used in conjunction with HelloCustom to apply custom specs.
// Fields of TLSExtensions that are slices/pointers are shared across different connections with
// same ClientHelloSpec. It is advised to use different specs and avoid any shared state.
func (uconn *UConn) ApplyPreset(p *ClientHelloSpec) error {
	var err error

	err = uconn.SetTLSVers(p.TLSVersMin, p.TLSVersMax, p.Extensions)
	if err != nil {
		return err
	}

	privateHello, ecdheParams, err := uconn.makeClientHello()
	if err != nil {
		return err
	}
	uconn.HandshakeState.Hello = privateHello.getPublicPtr()
	uconn.HandshakeState.State13.EcdheParams = ecdheParams
	uconn.HandshakeState.State13.KeySharesEcdheParams = make(KeySharesEcdheParameters, 2)
	hello := uconn.HandshakeState.Hello
	session := uconn.HandshakeState.Session

	switch len(hello.Random) {
	case 0:
		hello.Random = make([]byte, 32)
		_, err := io.ReadFull(uconn.config.rand(), hello.Random)
		if err != nil {
			return errors.New("tls: short read from Rand: " + err.Error())
		}
	case 32:
	// carry on
	default:
		return errors.New("ClientHello expected length: 32 bytes. Got: " +
			strconv.Itoa(len(hello.Random)) + " bytes")
	}
	if len(hello.CipherSuites) == 0 {
		hello.CipherSuites = defaultCipherSuites
	}
	if len(hello.CompressionMethods) == 0 {
		hello.CompressionMethods = []uint8{CompressionNone}
	}

	// Currently, GREASE is assumed to come from BoringSSL
	grease_bytes := make([]byte, 2*ssl_grease_last_index)
	grease_extensions_seen := 0
	_, err = io.ReadFull(uconn.config.rand(), grease_bytes)
	if err != nil {
		return errors.New("tls: short read from Rand: " + err.Error())
	}
	for i := range uconn.greaseSeed {
		uconn.greaseSeed[i] = binary.LittleEndian.Uint16(grease_bytes[2*i : 2*i+2])
	}
	if GetBoringGREASEValue(uconn.greaseSeed, ssl_grease_extension1) == GetBoringGREASEValue(uconn.greaseSeed, ssl_grease_extension2) {
		uconn.greaseSeed[ssl_grease_extension2] ^= 0x1010
	}

	hello.CipherSuites = make([]uint16, len(p.CipherSuites))
	copy(hello.CipherSuites, p.CipherSuites)
	for i := range hello.CipherSuites {
		if isGREASEUint16(hello.CipherSuites[i]) { // just in case the user set a GREASE value instead of unGREASEd
			hello.CipherSuites[i] = GetBoringGREASEValue(uconn.greaseSeed, ssl_grease_cipher)
		}
	}
	uconn.GetSessionID = p.GetSessionID
	uconn.Extensions = make([]TLSExtension, len(p.Extensions))
	copy(uconn.Extensions, p.Extensions)

	// Check whether NPN extension actually exists
	var haveNPN bool

	// reGrease, and point things to each other
	for _, e := range uconn.Extensions {
		switch ext := e.(type) {
		case *SNIExtension:
			if ext.ServerName == "" {
				ext.ServerName = uconn.config.ServerName
			}
		case *UtlsGREASEExtension:
			switch grease_extensions_seen {
			case 0:
				ext.Value = GetBoringGREASEValue(uconn.greaseSeed, ssl_grease_extension1)
			case 1:
				ext.Value = GetBoringGREASEValue(uconn.greaseSeed, ssl_grease_extension2)
				ext.Body = []byte{0}
			default:
				return errors.New("at most 2 grease extensions are supported")
			}
			grease_extensions_seen += 1
		case *SessionTicketExtension:
			if session == nil && uconn.config.ClientSessionCache != nil {
				cacheKey := clientSessionCacheKey(uconn.RemoteAddr(), uconn.config)
				session, _ = uconn.config.ClientSessionCache.Get(cacheKey)
				// TODO: use uconn.loadSession(hello.getPrivateObj()) to support TLS 1.3 PSK-style resumption
			}
			err := uconn.SetSessionState(session)
			if err != nil {
				return err
			}
		case *SupportedCurvesExtension:
			for i := range ext.Curves {
				if isGREASEUint16(uint16(ext.Curves[i])) {
					ext.Curves[i] = CurveID(GetBoringGREASEValue(uconn.greaseSeed, ssl_grease_group))
				}
			}
		case *KeyShareExtension:
			preferredCurveIsSet := false
			for i := range ext.KeyShares {
				curveID := ext.KeyShares[i].Group
				if isGREASEUint16(uint16(curveID)) { // just in case the user set a GREASE value instead of unGREASEd
					ext.KeyShares[i].Group = CurveID(GetBoringGREASEValue(uconn.greaseSeed, ssl_grease_group))
					continue
				}
				if len(ext.KeyShares[i].Data) > 1 {
					continue
				}

				ecdheParams, err := generateECDHEParameters(uconn.config.rand(), curveID)
				if err != nil {
					return fmt.Errorf("unsupported Curve in KeyShareExtension: %v."+
						"To mimic it, fill the Data(key) field manually", curveID)
				}
				uconn.HandshakeState.State13.KeySharesEcdheParams.AddEcdheParams(curveID, ecdheParams)
				ext.KeyShares[i].Data = ecdheParams.PublicKey()
				if !preferredCurveIsSet {
					// only do this once for the first non-grease curve
					uconn.HandshakeState.State13.EcdheParams = ecdheParams
					preferredCurveIsSet = true
				}
			}
		case *SupportedVersionsExtension:
			for i := range ext.Versions {
				if isGREASEUint16(ext.Versions[i]) { // just in case the user set a GREASE value instead of unGREASEd
					ext.Versions[i] = GetBoringGREASEValue(uconn.greaseSeed, ssl_grease_version)
				}
			}
		case *NPNExtension:
			haveNPN = true
		}
	}

	// The default golang behavior in makeClientHello always sets NextProtoNeg if NextProtos is set,
	// but NextProtos is also used by ALPN and our spec nmay not actually have a NPN extension
	hello.NextProtoNeg = haveNPN

	return nil
}

func (uconn *UConn) generateRandomizedSpec() (ClientHelloSpec, error) {
	return generateRandomizedSpec(&uconn.ClientHelloID, uconn.serverName, uconn.HandshakeState.Session, uconn.config.NextProtos)
}

func generateRandomizedSpec(
	id *ClientHelloID,
	serverName string,
	session *ClientSessionState,
	nextProtos []string,
) (ClientHelloSpec, error) {
	p := ClientHelloSpec{}

	if id.Seed == nil {
		seed, err := NewPRNGSeed()
		if err != nil {
			return p, err
		}
		id.Seed = seed
	}

	r, err := newPRNGWithSeed(id.Seed)
	if err != nil {
		return p, err
	}

	if id.Weights == nil {
		id.Weights = &DefaultWeights
	}

	var WithALPN bool
	switch id.Client {
	case helloRandomizedALPN:
		WithALPN = true
	case helloRandomizedNoALPN:
		WithALPN = false
	case helloRandomized:
		if r.FlipWeightedCoin(id.Weights.Extensions_Append_ALPN) {
			WithALPN = true
		} else {
			WithALPN = false
		}
	default:
		return p, fmt.Errorf("using non-randomized ClientHelloID %v to generate randomized spec", id.Client)
	}

	p.CipherSuites = make([]uint16, len(defaultCipherSuites))
	copy(p.CipherSuites, defaultCipherSuites)
	shuffledSuites, err := shuffledCiphers(r)
	if err != nil {
		return p, err
	}

	if r.FlipWeightedCoin(id.Weights.TLSVersMax_Set_VersionTLS13) {
		p.TLSVersMin = VersionTLS10
		p.TLSVersMax = VersionTLS13
		tls13ciphers := make([]uint16, len(defaultCipherSuitesTLS13))
		copy(tls13ciphers, defaultCipherSuitesTLS13)
		r.rand.Shuffle(len(tls13ciphers), func(i, j int) {
			tls13ciphers[i], tls13ciphers[j] = tls13ciphers[j], tls13ciphers[i]
		})
		// appending TLS 1.3 ciphers before TLS 1.2, since that's what popular implementations do
		shuffledSuites = append(tls13ciphers, shuffledSuites...)

		// TLS 1.3 forbids RC4 in any configurations
		shuffledSuites = removeRC4Ciphers(shuffledSuites)
	} else {
		p.TLSVersMin = VersionTLS10
		p.TLSVersMax = VersionTLS12
	}

	p.CipherSuites = removeRandomCiphers(r, shuffledSuites, id.Weights.CipherSuites_Remove_RandomCiphers)

	sni := SNIExtension{serverName}
	sessionTicket := SessionTicketExtension{Session: session}

	sigAndHashAlgos := []SignatureScheme{
		ECDSAWithP256AndSHA256,
		PKCS1WithSHA256,
		ECDSAWithP384AndSHA384,
		PKCS1WithSHA384,
		PKCS1WithSHA1,
		PKCS1WithSHA512,
	}

	if r.FlipWeightedCoin(id.Weights.SigAndHashAlgos_Append_ECDSAWithSHA1) {
		sigAndHashAlgos = append(sigAndHashAlgos, ECDSAWithSHA1)
	}
	if r.FlipWeightedCoin(id.Weights.SigAndHashAlgos_Append_ECDSAWithP521AndSHA512) {
		sigAndHashAlgos = append(sigAndHashAlgos, ECDSAWithP521AndSHA512)
	}
	if r.FlipWeightedCoin(id.Weights.SigAndHashAlgos_Append_PSSWithSHA256) || p.TLSVersMax == VersionTLS13 {
		// https://tools.ietf.org/html/rfc8446 says "...RSASSA-PSS (which is mandatory in TLS 1.3)..."
		sigAndHashAlgos = append(sigAndHashAlgos, PSSWithSHA256)
		if r.FlipWeightedCoin(id.Weights.SigAndHashAlgos_Append_PSSWithSHA384_PSSWithSHA512) {
			// these usually go together
			sigAndHashAlgos = append(sigAndHashAlgos, PSSWithSHA384)
			sigAndHashAlgos = append(sigAndHashAlgos, PSSWithSHA512)
		}
	}

	r.rand.Shuffle(len(sigAndHashAlgos), func(i, j int) {
		sigAndHashAlgos[i], sigAndHashAlgos[j] = sigAndHashAlgos[j], sigAndHashAlgos[i]
	})
	sigAndHash := SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: sigAndHashAlgos}

	status := StatusRequestExtension{}
	sct := SCTExtension{}
	ems := UtlsExtendedMasterSecretExtension{}
	points := SupportedPointsExtension{SupportedPoints: []byte{PointFormatUncompressed}}

	curveIDs := []CurveID{}
	if r.FlipWeightedCoin(id.Weights.CurveIDs_Append_X25519) || p.TLSVersMax == VersionTLS13 {
		curveIDs = append(curveIDs, X25519)
	}
	curveIDs = append(curveIDs, CurveP256, CurveP384)
	if r.FlipWeightedCoin(id.Weights.CurveIDs_Append_CurveP521) {
		curveIDs = append(curveIDs, CurveP521)
	}

	curves := SupportedCurvesExtension{curveIDs}

	padding := UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle}
	reneg := RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient}

	p.Extensions = []TLSExtension{
		&sni,
		&sessionTicket,
		&sigAndHash,
		&points,
		&curves,
	}

	if WithALPN {
		if len(nextProtos) == 0 {
			// if user didn't specify alpn yet, choose something popular
			nextProtos = []string{"h2", "http/1.1"}
		}
		alpn := ALPNExtension{AlpnProtocols: nextProtos}
		p.Extensions = append(p.Extensions, &alpn)
	}

	if r.FlipWeightedCoin(id.Weights.Extensions_Append_Padding) || p.TLSVersMax == VersionTLS13 {
		// always include for TLS 1.3, since TLS 1.3 ClientHellos are often over 256 bytes
		// and that's when padding is required to work around buggy middleboxes
		p.Extensions = append(p.Extensions, &padding)
	}
	if r.FlipWeightedCoin(id.Weights.Extensions_Append_Status) {
		p.Extensions = append(p.Extensions, &status)
	}
	if r.FlipWeightedCoin(id.Weights.Extensions_Append_SCT) {
		p.Extensions = append(p.Extensions, &sct)
	}
	if r.FlipWeightedCoin(id.Weights.Extensions_Append_Reneg) {
		p.Extensions = append(p.Extensions, &reneg)
	}
	if r.FlipWeightedCoin(id.Weights.Extensions_Append_EMS) {
		p.Extensions = append(p.Extensions, &ems)
	}
	if p.TLSVersMax == VersionTLS13 {
		ks := KeyShareExtension{[]KeyShare{
			{Group: X25519}, // the key for the group will be generated later
		}}
		if r.FlipWeightedCoin(id.Weights.FirstKeyShare_Set_CurveP256) {
			// do not ADD second keyShare because crypto/tls does not support multiple ecdheParams
			// TODO: add it back when they implement multiple keyShares, or implement it oursevles
			// ks.KeyShares = append(ks.KeyShares, KeyShare{Group: CurveP256})
			ks.KeyShares[0].Group = CurveP256
		}
		pskExchangeModes := PSKKeyExchangeModesExtension{[]uint8{pskModeDHE}}
		supportedVersionsExt := SupportedVersionsExtension{
			Versions: makeSupportedVersions(p.TLSVersMin, p.TLSVersMax),
		}
		p.Extensions = append(p.Extensions, &ks, &pskExchangeModes, &supportedVersionsExt)

		// Randomly add an ALPS extension. ALPS is TLS 1.3-only and may only
		// appear when an ALPN extension is present
		// (https://datatracker.ietf.org/doc/html/draft-vvv-tls-alps-01#section-3).
		// ALPS is a draft specification at this time, but appears in
		// Chrome/BoringSSL.
		if WithALPN {

			// ALPS is a new addition to generateRandomizedSpec. Use a salted
			// seed to create a new, independent PRNG, so that a seed used
			// with the previous version of generateRandomizedSpec will
			// produce the exact same spec as long as ALPS isn't selected.
			r, err := newPRNGWithSaltedSeed(id.Seed, "ALPS")
			if err != nil {
				return p, err
			}
			if r.FlipWeightedCoin(id.Weights.Extensions_Append_ALPS) {
				// As with the ALPN case above, default to something popular
				// (unlike ALPN, ALPS can't yet be specified in uconn.config).
				alps := &ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}}
				p.Extensions = append(p.Extensions, alps)
			}
		}

		// TODO: randomly add DelegatedCredentialsExtension, once it is
		// sufficiently popular.
	}
	r.rand.Shuffle(len(p.Extensions), func(i, j int) {
		p.Extensions[i], p.Extensions[j] = p.Extensions[j], p.Extensions[i]
	})

	return p, nil
}

func removeRandomCiphers(r *prng, s []uint16, maxRemovalProbability float64) []uint16 {
	// removes elements in place
	// probability to remove increases for further elements
	// never remove first cipher
	if len(s) <= 1 {
		return s
	}

	// remove random elements
	floatLen := float64(len(s))
	sliceLen := len(s)
	for i := 1; i < sliceLen; i++ {
		if r.FlipWeightedCoin(maxRemovalProbability * float64(i) / floatLen) {
			s = append(s[:i], s[i+1:]...)
			sliceLen--
			i--
		}
	}
	return s[:sliceLen]
}

func shuffledCiphers(r *prng) ([]uint16, error) {
	ciphers := make(sortableCiphers, len(cipherSuites))
	perm := r.Perm(len(cipherSuites))
	for i, suite := range cipherSuites {
		ciphers[i] = sortableCipher{suite: suite.id,
			isObsolete: ((suite.flags & suiteTLS12) == 0),
			randomTag:  perm[i]}
	}
	sort.Sort(ciphers)
	return ciphers.GetCiphers(), nil
}

type sortableCipher struct {
	isObsolete bool
	randomTag  int
	suite      uint16
}

type sortableCiphers []sortableCipher

func (ciphers sortableCiphers) Len() int {
	return len(ciphers)
}

func (ciphers sortableCiphers) Less(i, j int) bool {
	if ciphers[i].isObsolete && !ciphers[j].isObsolete {
		return false
	}
	if ciphers[j].isObsolete && !ciphers[i].isObsolete {
		return true
	}
	return ciphers[i].randomTag < ciphers[j].randomTag
}

func (ciphers sortableCiphers) Swap(i, j int) {
	ciphers[i], ciphers[j] = ciphers[j], ciphers[i]
}

func (ciphers sortableCiphers) GetCiphers() []uint16 {
	cipherIDs := make([]uint16, len(ciphers))
	for i := range ciphers {
		cipherIDs[i] = ciphers[i].suite
	}
	return cipherIDs
}

func removeRC4Ciphers(s []uint16) []uint16 {
	// removes elements in place
	sliceLen := len(s)
	for i := 0; i < sliceLen; i++ {
		cipher := s[i]
		if cipher == TLS_ECDHE_ECDSA_WITH_RC4_128_SHA ||
			cipher == TLS_ECDHE_RSA_WITH_RC4_128_SHA ||
			cipher == TLS_RSA_WITH_RC4_128_SHA {
			s = append(s[:i], s[i+1:]...)
			sliceLen--
			i--
		}
	}
	return s[:sliceLen]
}
