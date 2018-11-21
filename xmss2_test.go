// Copyright (c) 2018 Aidos Developer

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
	"github.com/AidosKuneen/numcpu"
	"runtime"
	"testing"
)

func TestXMSS2(t *testing.T) {
	n := numcpu.NumCPU()
	npref := runtime.GOMAXPROCS(n)
	seed := generateSeed()
	sk, pk := NewXMSSKeyPair(10, seed)
	msg := []byte("This is a test for XMSS.")
	var pre []byte
	for i := 0; i < 1<<10; i++ {
		sig := sk.Sign(msg)
		if !pk.Verify(sig, msg) {
			t.Error("XMSS sig is incorrect")
		}
		if pre != nil && bytes.Equal(pre, sig) {
			t.Error("sig must not be same")
		}
		pre = sig
	}
	runtime.GOMAXPROCS(npref)
}

func TestXMSS3(t *testing.T) {
	n := numcpu.NumCPU()
	npref := runtime.GOMAXPROCS(n)
	seed := generateSeed()
	sk, pk := NewXMSSKeyPair(10, seed)
	msg := []byte("This is a test for XMSS.")
	sig := sk.Sign(msg)
	msg[0] = 0
	if pk.Verify(sig, msg) {
		t.Error("XMSS sig is incorrect")
	}
	runtime.GOMAXPROCS(npref)
}

func TestXMSS4(t *testing.T) {
	n := numcpu.NumCPU()
	npref := runtime.GOMAXPROCS(n)
	seed := generateSeed()
	sk, pk := NewXMSSKeyPair(2, seed)
	msg := []byte("This is a test for XMSS.")
	sig := sk.Sign(msg)
	if !pk.Verify(sig, msg) {
		t.Error("XMSS sig is incorrect")
	}
	msg[0] = 0
	if pk.Verify(sig, msg) {
		t.Error("XMSS sig is incorrect")
	}
	runtime.GOMAXPROCS(npref)
}
func TestXMSS16(t *testing.T) {
	n := numcpu.NumCPU()
	npref := runtime.GOMAXPROCS(n)
	seed := generateSeed()
	sk, pk := NewXMSSKeyPair(16, seed)
	msg := []byte("This is a test for XMSS height=16.")
	sig := sk.Sign(msg)
	if !pk.Verify(sig, msg) {
		t.Error("XMSS sig is incorrect")
	}
	runtime.GOMAXPROCS(npref)
}

func BenchmarkXMSS16(b *testing.B) {
	n := numcpu.NumCPU()
	npref := runtime.GOMAXPROCS(n)
	seed := generateSeed()
	b.ResetTimer()
	_, _ = NewXMSSKeyPair(16, seed)
	runtime.GOMAXPROCS(npref)
}

func BenchmarkXMSS16Sign(b *testing.B) {
	n := numcpu.NumCPU()
	npref := runtime.GOMAXPROCS(n)
	seed := generateSeed()
	sk, _ := NewXMSSKeyPair(16, seed)
	msg := []byte("This is a test for XMSS.")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sk.Sign(msg)
	}
	runtime.GOMAXPROCS(npref)
}
func BenchmarkXMSS16Veri(b *testing.B) {
	n := numcpu.NumCPU()
	npref := runtime.GOMAXPROCS(n)
	seed := generateSeed()
	sk, pk := NewXMSSKeyPair(16, seed)
	msg := []byte("This is a test for XMSS.")
	sig := sk.Sign(msg)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pk.Verify(sig, msg)
	}
	runtime.GOMAXPROCS(npref)
}

func BenchmarkXMSS20(b *testing.B) {
	n := numcpu.NumCPU()
	npref := runtime.GOMAXPROCS(n)
	seed := generateSeed()
	b.ResetTimer()
	_, _ = NewXMSSKeyPair(20, seed)
	runtime.GOMAXPROCS(npref)
}

func BenchmarkXMSS10(b *testing.B) {
	n := numcpu.NumCPU()
	npref := runtime.GOMAXPROCS(n)
	seed := generateSeed()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = NewXMSSKeyPair(10, seed)
	}
	runtime.GOMAXPROCS(npref)
}
func BenchmarkXMSS10Sign(b *testing.B) {
	n := numcpu.NumCPU()
	npref := runtime.GOMAXPROCS(n)
	seed := generateSeed()
	sk, _ := NewXMSSKeyPair(10, seed)
	msg := []byte("This is a test for XMSS.")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sk.Sign(msg)
	}
	runtime.GOMAXPROCS(npref)
}
func BenchmarkXMSS10Veri(b *testing.B) {
	n := numcpu.NumCPU()
	npref := runtime.GOMAXPROCS(n)
	seed := generateSeed()
	sk, pk := NewXMSSKeyPair(10, seed)
	msg := []byte("This is a test for XMSS.")
	sig := sk.Sign(msg)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pk.Verify(sig, msg)
	}
	runtime.GOMAXPROCS(npref)
}
