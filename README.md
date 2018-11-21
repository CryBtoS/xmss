XMSS (eXtended Merkle Signature Scheme)
=====

## Overview

This library is for creating keys, signing messages and verifing the signature by XMSS and XMSS^MT in Go.
This repository was forked from github.com/AidosKuneen/xmss.

This code implements `XMSS-SHA2_*_256` and `XMSSMT-SHA2_*/*_256`
 described on  [XMSS: eXtended Merkle Signature Scheme (RFC 8391)](https://datatracker.ietf.org/doc/rfc8391/).
 This code should be much faster than the [XMSS reference code](https://github.com/joostrijneveld/xmss-reference).
 by using [SSE extention](https://github.com/minio/sha256-simd) and block level optimizations in SHA256 with multi threadings.


## Requirements

* git
* go 1.9+

are required to compile.


## Install
    $ go get -u github.com/CryBtoS/xmss


## Usage

```go
	import "github.com/CryBtoS/xmss"

	seed := []byte{0x01,0x02...}
	sk, pk := NewXMSSKeyPair(10, seed)
    msg := []byte("This is a test for XMSS.")
	sig := sk.Sign(msg)
	if !pk.Verify(sig, msg) {
        t.Error("XMSS sig is incorrect")
    }
```