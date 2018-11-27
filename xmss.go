// Copyright (c) 2018 Benjamin Schlosser

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
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

type XMSSParameters struct {
	//oid
	Height uint32
}

// XMSS private key
type PrivateKey struct {
	PublicKey       // public part (pubPRF, root)
	msgPRF  *prf    // prf for randomization of message digest
	wotsPRF *prf    // prf for generating WOTS+ private keys
	m       *merkle // state
}

type PrivateKeyExport struct {
	PublicKeyExport
	Index         uint32 // index of next unused WOTS+ private key
	SecretKeyPRF  []byte // seed for randomization of message digest
	SecretKeySeed []byte // seed for generating WOTS+ private keys
}

// XMSS public key
type PublicKey struct {
	XMSSParameters
	// TODO: check if the byte array here is ok or a prf-object has to be created hier
	publicSeed []byte // publicSeed for randomization of hashes
	root       []byte // root of merkle tree
}

type PublicKeyExport struct {
	XMSSParameters
	PublicSeed []byte // publicSeed for randomization of hashes
	Root       []byte // root of merkle tree
}

func NewXMSSKeyPair(height uint32, privateSeed []byte) (*PrivateKey, *PublicKey) {
	mac := hmac.New(sha256.New, privateSeed)
	if _, err := mac.Write([]byte{1}); err != nil {
		panic(err)
	}
	secretKeySeed := mac.Sum(nil)
	mac.Reset()
	if _, err := mac.Write([]byte{2}); err != nil {
		panic(err)
	}
	secretKeyPRF := mac.Sum(nil)
	mac.Reset()
	if _, err := mac.Write([]byte{3}); err != nil {
		panic(err)
	}
	publicSeed := mac.Sum(nil)
	return NewXMSSKeyPairWithParams(height, secretKeySeed, secretKeyPRF, publicSeed, 0, 0)
}

func NewXMSSKeyPairWithParams(height uint32, secretKeySeed, secretKeyPRF, publicSeed []byte, layer uint32, tree uint64) (*PrivateKey, *PublicKey) {
	publicKey := PublicKey{
		XMSSParameters: XMSSParameters{Height: height},
		root:           make([]byte, 32),
		publicSeed:     publicSeed,
	}
	privateKey := PrivateKey{
		PublicKey: publicKey,
		msgPRF:    newPRF(secretKeyPRF),
		wotsPRF:   newPRF(secretKeySeed),
	}
	privateKey.initMerkle(height, layer, tree)

	return &privateKey, &publicKey
}

// Public() returns the public key corresponding to priv
func (priv *PrivateKey) Public() crypto.PublicKey {
	return &priv.PublicKey
}

func (priv *PrivateKey) Sign(msg []byte) ([]byte) {
	index := make([]byte, 32)
	binary.BigEndian.PutUint32(index[28:], priv.m.leaf)
	r := make([]byte, 32*3)
	priv.msgPRF.sum(index, r)
	copy(r[32:], priv.root)
	copy(r[64:], index)
	hmsg := hashMsg(r, msg)
	sigBody := priv.createSignatureBody(hmsg)
	sig := &xmssSig{
		index:       priv.m.leaf,
		r:           r[:32],
		xmssSigBody: sigBody,
	}
	result := sig.bytes()
	priv.traverse()
	return result
}

func (priv *PrivateKey) createSignatureBody(hmsg []byte) *xmssSigBody {
	wsk := make(wotsPrivKey, wlen)
	for i := range wsk {
		wsk[i] = make([]byte, 32)
	}
	addrs := make(addr, 32)
	addrs.set(adrLayer, priv.m.layer)
	addrs.setTree(priv.m.tree)
	addrs.set(adrOTS, priv.m.leaf)
	priv.newWotsPrivKey(addrs, wsk)
	pubPRF := newPRF(priv.publicSeed)
	sig := wsk.sign(hmsg, pubPRF, addrs)
	return &xmssSigBody{
		sig:  sig,
		auth: priv.m.auth,
	}
}

func (priv *PrivateKey) newWotsPrivKey(addrs addr, sk wotsPrivKey) {
	s := make([]byte, 32)
	priv.wotsPRF.sum(addrs, s)
	p := newPRF(s)
	for i := range sk {
		p.sumInt(uint32(i), sk[i])
	}
}

func (priv *PrivateKey) Export() *PrivateKeyExport {
	return &PrivateKeyExport{
		PublicKeyExport: PublicKeyExport{
			XMSSParameters: priv.XMSSParameters,
			PublicSeed:     priv.publicSeed,
			Root:           priv.root,
		},
		Index:         priv.m.leaf,
		SecretKeyPRF:  priv.msgPRF.seed,
		SecretKeySeed: priv.wotsPRF.seed,
	}
}

func (priv *PrivateKey) Import(key *PrivateKeyExport) {
	priv.XMSSParameters = key.XMSSParameters
	priv.publicSeed = key.PublicSeed
	priv.root = key.Root
	priv.m.leaf = key.Index
	priv.msgPRF = newPRF(key.SecretKeyPRF)
	priv.wotsPRF = newPRF(key.SecretKeySeed)
	priv.initMerkle(priv.Height, 0, 0)
}

func (pub *PublicKey) Verify(bsig, msg []byte) bool {
	sig, err := bytes2sig(bsig, byte(pub.XMSSParameters.Height))
	if err != nil {
		return false
	}
	prf := newPRF(pub.publicSeed)
	r := make([]byte, 32*3)
	copy(r, sig.r)
	copy(r[32:], pub.root)
	binary.BigEndian.PutUint32(r[64+28:], sig.index)
	hmsg := hashMsg(r, msg)
	root := rootFromSig(sig.index, hmsg, sig.xmssSigBody, prf, 0, 0)
	return bytes.Equal(root, pub.root)
}

func (pub *PublicKey) Export() *PublicKeyExport {
	return &PublicKeyExport{
		XMSSParameters: pub.XMSSParameters,
		PublicSeed:     pub.publicSeed,
		Root:           pub.root,
	}
}

func (pub *PublicKey) Import(key *PublicKeyExport) {
	pub.Height = key.Height
	pub.publicSeed = key.PublicSeed
	pub.root = key.Root
}

func randHash(left, right []byte, p *prf, addrs addr, out []byte) {
	addrs.set(adrKM, 0)
	key := make([]byte, 32)
	p.sum(addrs, key)
	addrs.set(adrKM, 1)
	bm0 := make([]byte, 32)
	p.sum(addrs, bm0)
	addrs.set(adrKM, 2)
	bm1 := make([]byte, 32)
	p.sum(addrs, bm1)

	lxor := make([]byte, 32)
	xorWords(lxor, left, bm0)
	rxor := make([]byte, 32)
	xorWords(rxor, right, bm1)
	hashH(key, lxor, rxor, out)
}

func (pk wotsPubKey) ltree(p *prf, addrs addr) []byte {
	var height uint32
	addrs.set(adrHeight, 0)
	var l uint32
	for l = wlen; l > 1; l = (l >> 1) + (l & 0x1) {
		var i uint32
		for i = 0; i < l>>1; i++ {
			addrs.set(adrIndex, i)
			randHash(pk[2*i], pk[2*i+1], p, addrs, pk[i])
		}
		if l&0x1 == 1 {
			copy(pk[l>>1], pk[l-1])
		}
		height++
		addrs.set(adrHeight, height)
	}
	return pk[0]
}

type xmssSigBody struct {
	sig  wotsSig
	auth [][]byte
}

type xmssSig struct {
	index uint32
	r     []byte
	*xmssSigBody
}

func (x *xmssSig) bytes() []byte {
	sigSize := 4 + n + wlen*n + len(x.auth)*n
	sig := make([]byte, sigSize)
	binary.BigEndian.PutUint32(sig, x.index)
	copy(sig[4:], x.r)
	sigBody := x.xmssSigBody.bytes()
	copy(sig[4+n:], sigBody)
	return sig
}

func (x *xmssSigBody) bytes() []byte {
	sigSize := wlen*n + len(x.auth)*n
	sig := make([]byte, sigSize)
	for i, s := range x.sig {
		copy(sig[i*n:], s)
	}
	for i, s := range x.auth {
		copy(sig[wlen*n+i*n:], s)
	}
	return sig
}

func bytes2sig(b []byte, h byte) (*xmssSig, error) {
	height := (len(b) - (4 + n + wlen*n)) >> 5
	if height != int(h) {
		return nil, errors.New("invalid length of bytes")
	}
	body := bytes2sigBody(b[4+n:], height)
	sig := &xmssSig{
		index:       binary.BigEndian.Uint32(b),
		r:           b[4 : 4+n],
		xmssSigBody: body,
	}
	return sig, nil
}

func bytes2sigBody(b []byte, height int) *xmssSigBody {
	body := &xmssSigBody{
		sig:  make([][]byte, wlen),
		auth: make([][]byte, height),
	}
	for i := 0; i < wlen; i++ {
		body.sig[i] = b[i*n : (i+1)*n]
	}
	for i := 0; i < height; i++ {
		body.auth[i] = b[n*wlen+n*i : n*wlen+n*(i+1)]
	}
	return body
}

func rootFromSig(idx uint32, hmsg []byte, body *xmssSigBody, prf *prf, layer uint32, tree uint64) []byte {
	addrs := make(addr, 32)
	addrs.set(adrLayer, layer)
	addrs.setTree(tree)
	addrs.set(adrOTS, idx)
	pkOTS := body.sig.pubkey(hmsg, prf, addrs)
	addrs.set(adrType, 1)
	addrs.set(adrLtree, idx)
	node0 := pkOTS.ltree(prf, addrs)
	addrs.set(adrType, 2)
	addrs.set(adrLtree, 0)
	var k uint32
	for k = 0; k < uint32(len(body.auth)); k++ {
		addrs.set(adrHeight, k)
		addrs.set(adrIndex, idx>>1)
		if idx&0x1 == 0 {
			randHash(node0, body.auth[k], prf, addrs, node0)
		} else {
			randHash(body.auth[k], node0, prf, addrs, node0)
		}
		idx >>= 1
	}
	return node0
}
