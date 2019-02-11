// Copyright (c) 2019 Benjamin Schlosser

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

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

func MarshalPKCS8PrivateKey(key *PrivateKey) ([]byte, error) {
	if key == nil {
		return nil, errors.New("invalid xmss private key - it must be different from nil")
	}
	asn1Bytes, err := marshalXMSSPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("error marshalling XMSS private key to asn1 [%s]", err)
	}

	var pkcs8Key pkcs8
	pkcs8Key.Version = 0
	pkcs8Key.Algo.Algorithm = OIDBCXMSS
	pkcs8Key.PrivateKey = asn1Bytes

	pkcs8Bytes, err := asn1.Marshal(pkcs8Key)
	if err != nil {
		return nil, fmt.Errorf("error marshalling XMSS private key to asn1 [%s]", err)
	}
	return pkcs8Bytes, nil
}

func marshalXMSSPrivateKey(key *PrivateKey) ([]byte, error) {
	keyExport := key.Export()

	pkcs8XMSSKey := pkcs8XMSSPrivateKey{
		Version: 0,
		Data: pkcs8XMSSPrivateKeyData{
			Index: int(keyExport.Index),
			SecretKeySeed: keyExport.SecretKeySeed,
			SecretKeyPRF: keyExport.SecretKeyPRF,
			PublicSeed: keyExport.PublicSeed,
			Root: keyExport.Root,
		},
		BdsState: nil,
	}

	return asn1.Marshal(pkcs8XMSSKey)
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