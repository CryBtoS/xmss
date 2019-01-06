package xmss

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
)

var (
	OIDBCXMSS = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 22554, 2, 2}
)

// pkcs8 reflects an ASN.1, PKCS#8 PrivateKey. See RFC 5208.
type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
}

func ParsePKCS8PrivateKey(der []byte) (key interface{}, err error) {
	var privKey pkcs8
	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		return nil, fmt.Errorf("XMSS PKCS#8 parser: failed to unmarshal private key: %s", err)
	}

	if privKey.Algo.Algorithm.Equal(OIDBCXMSS) {
		key, err = parseXMSSPrivateKey(privKey.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("x509: PKCS#8 parsing of xmss private key failed: %s", err)
		}
		return key, err
	}

	return nil, fmt.Errorf("x509: PKCS#8 parsing of xmss private key failed")
}

type pkcs8XMSSPrivateKey struct {
	Version  int
	Data     pkcs8XMSSPrivateKeyData
	BdsState []byte `asn1:"explicit"`
}

type pkcs8XMSSPrivateKeyData struct {
	Index         int
	SecretKeySeed []byte
	SecretKeyPRF  []byte
	PublicSeed    []byte
	Root          []byte
}

func parseXMSSPrivateKey(der []byte) (*PrivateKey, error) {
	var privKey pkcs8XMSSPrivateKey
	rest, err := asn1.Unmarshal(der, &privKey)
	if len(rest) > 0 {
		return nil, asn1.SyntaxError{Msg: "trailing data"}
	}
	if err != nil {
		return nil, err
	}

	privKeyExport := &PrivateKeyExport{
		PublicKeyExport: PublicKeyExport{
			XMSSParameters: XMSSParameters{Height: 10},
			PublicSeed:     privKey.Data.PublicSeed,
			Root:           privKey.Data.Root,
		},
		Index:         uint32(privKey.Data.Index),
		SecretKeySeed: privKey.Data.SecretKeySeed,
		SecretKeyPRF:  privKey.Data.SecretKeyPRF,
	}

	key := new(PrivateKey)
	key.Import(privKeyExport)

	return key, nil
}

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

func ParsePKIXPublicKey(der []byte) (pub interface{}, err error) {
	var pki publicKeyInfo
	if rest, err := asn1.Unmarshal(der, &pki); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, asn1.SyntaxError{Msg: "trailing data"}
	}
	if pki.Algorithm.Algorithm.Equal(OIDBCXMSS) {
		pub, err = parseXMSSPublicKey(pki.PublicKey.Bytes)
		if err != nil {
			return nil, fmt.Errorf("x509: PKCS#8 parsing of xmss public key failed: %s", err)
		}
		return pub, err
	}
	return nil, errors.New("x509: public key algorithm is not XMSS")
}

type xmssPublicKeyData struct {
	Version    int
	PublicSeed []byte
	Root       []byte
}

func parseXMSSPublicKey(der []byte) (*PublicKey, error) {
	var pubKey xmssPublicKeyData
	rest, err := asn1.Unmarshal(der, &pubKey)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after XMSS public key")
	}

	pubKeyExport := &PublicKeyExport{
		XMSSParameters: XMSSParameters{Height: 10},
		PublicSeed:     pubKey.PublicSeed,
		Root:           pubKey.Root,
	}

	key := new(PublicKey)
	key.Import(pubKeyExport)

	return key, nil
}