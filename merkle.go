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
	"math"
	"runtime"
	"sync"
)

//nh represents a node in a merkle tree.
type nh struct {
	node   []byte
	height uint32
	index  uint32
}

//stack is a stack to use in merkle traversing.
type stack struct {
	stack  []*nh
	height uint32
	leaf   uint32
	layer  uint32
	tree   uint64
}

func (s *stack) low() uint32 {
	if len(s.stack) == 0 {
		return s.height
	}
	if s.top().height == s.height {
		return math.MaxUint32
	}
	var min uint32 = math.MaxUint32
	for _, n := range s.stack {
		if n.height < min {
			min = n.height
		}
	}
	return min
}

func (s *stack) initialize(start uint32, height uint32) {
	s.leaf = start
	s.height = height
	s.stack = s.stack[:0]
}

func (s *stack) newleaf(priv *PrivateKey, isGo bool) {
	pk := make(wotsPubKey, wlen)
	sk := make(wotsPrivKey, wlen)
	for j := 0; j < wlen; j++ {
		pk[j] = make([]byte, n)
		sk[j] = make([]byte, n)
	}
	addrs := make(addr, 32)

	// addrs.set(adrType, 0)
	addrs.set(adrLayer, s.layer)
	addrs.setTree(s.tree)
	addrs.set(adrOTS, s.leaf)
	priv.newWotsPrivKey(addrs, sk)
	pubPRF := newPRF(priv.publicSeed)
	if isGo {
		sk.goNewWotsPubKey(pubPRF, addrs, pk)
	} else {
		sk.newWotsPubKey(pubPRF, addrs, pk)
	}
	addrs.set(adrType, 1)
	addrs.set(adrLtree, s.leaf)
	nn := pk.ltree(pubPRF, addrs)
	node := &nh{
		node:   make([]byte, 32),
		height: 0,
		index:  s.leaf,
	}
	copy(node.node, nn)
	s.push(node)
	s.leaf++
}

func (s *stack) update(nn uint64, priv *PrivateKey) {
	s.updateSub(nn, priv, func() {
		s.newleaf(priv, false)
	})
}

func (s *stack) goUpdate(nn uint64, priv *PrivateKey) {
	s.updateSub(nn, priv, func() {
		s.newleaf(priv, true)
	})
}

func (s *stack) updateSub(nn uint64, priv *PrivateKey, newleaf func()) {
	if len(s.stack) > 0 && (s.stack[len(s.stack)-1].height == s.height) {
		return
	}
	addrs := make(addr, 32)
	addrs.set(adrType, 2)
	addrs.set(adrLayer, s.layer)
	addrs.setTree(s.tree)
	pubPRF := newPRF(priv.publicSeed)
	for i := uint64(0); i < nn; i++ {
		if len(s.stack) >= 2 {
			right := s.top()
			left := s.nextTop()
			if left.height == right.height {
				node := &nh{
					node: make([]byte, 32),
				}
				node.index = right.index >> 1
				node.height = right.height + 1
				addrs.set(adrHeight, right.height)
				addrs.set(adrIndex, node.index)
				randHash(left.node, right.node, pubPRF, addrs, node.node)
				s.delete(2)
				s.push(node)
				continue
			}
		}
		newleaf()
	}
}
func (s *stack) top() *nh {
	return s.stack[len(s.stack)-1]
}
func (s *stack) nextTop() *nh {
	return s.stack[len(s.stack)-2]
}
func (s *stack) push(n *nh) {
	s.stack = append(s.stack, n)
}
func (s *stack) delete(i int) {
	for j := 0; j < i; j++ {
		s.stack[len(s.stack)-1-j] = nil
	}
	s.stack = s.stack[:len(s.stack)-i]
}

//merkle represents MerkleTree for XMSS.
type merkle struct {
	//leaf is the number of unused leaf.
	leaf   uint32
	height uint32
	stacks []*stack
	auth   [][]byte
	layer  uint32
	tree   uint64
}

func (priv *PrivateKey) initMerkle(h uint32, layer uint32, tree uint64) {
	m := &merkle{
		leaf:   0,
		height: h,
		stacks: make([]*stack, h),
		auth:   make([][]byte, h),
		layer:  layer,
		tree:   tree,
	}

	var wg sync.WaitGroup
	ncpu := runtime.GOMAXPROCS(-1)
	nproc := uint32(math.Log2(float64(ncpu)))
	if ncpu != (1 << nproc) {
		nproc++
	}
	if h <= nproc {
		nproc = 0
	}
	ntop := make([]*nh, (1<<nproc)-1)
	for i := uint32(1); i < (1 << nproc); i++ {
		wg.Add(1)
		go func(i uint32) {
			s := stack{
				stack:  make([]*nh, 0, (h-nproc)+1),
				height: h - nproc,
				leaf:   (1 << (h - nproc)) * i,
				layer:  m.layer,
				tree:   m.tree,
			}
			s.update(1<<(h-nproc+1)-1, priv)
			ntop[i-1] = s.top()
			wg.Done()
		}(i)
	}
	s := stack{
		stack:  make([]*nh, 0, h+1),
		height: h,
		leaf:   0,
		layer:  m.layer,
		tree:   m.tree,
	}
	for i := uint32(0); i < h; i++ {
		if i == h-nproc {
			wg.Wait()
		}
		s.update(1, priv)
		m.stacks[i] = &stack{
			stack:  make([]*nh, 0, i+1),
			height: i,
			leaf:   1 << i,
			layer:  m.layer,
			tree:   m.tree,
		}
		m.stacks[i].push(s.top())
		if i < h-nproc {
			s.update(1<<(i+1)-1, priv)
		} else {
			s.updateSub(1<<(i-(h-nproc)+1)-1, priv, func() {
				n := ntop[0]
				ntop = ntop[1:]
				s.push(n)
			})
		}
		m.auth[i] = make([]byte, 32)
		copy(m.auth[i], s.top().node)
	}
	s.update(1, priv)
	copy(priv.root, s.top().node)
	priv.m = m
}

func (m *merkle) refreshAuth() {
	var h uint32
	for h = 0; h < m.height; h++ {
		var pow uint32 = 1 << h
		if (m.leaf+1)&(pow-1) == 0 {
			m.auth[h] = m.stacks[h].top().node
			startnode := ((m.leaf + 1) + pow) ^ pow
			m.stacks[h].initialize(startnode, h)
		}
	}
}
func (priv *PrivateKey) build() {
	var i uint32
	for i = 0; i < ((2 * priv.m.height) - 1); i++ {
		var min uint32 = math.MaxUint32
		var h, focus uint32
		for h = 0; h < priv.m.height; h++ {
			low := priv.m.stacks[h].low()
			if low < min {
				min = low
				focus = h
			}
		}
		priv.m.stacks[focus].goUpdate(1, priv)
	}
}

//traverse refreshes auth and stacks and increment leaf number.
func (priv *PrivateKey) traverse() {
	priv.m.refreshAuth()
	priv.build()
	priv.m.leaf++
}
