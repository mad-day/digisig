/*
MIT License

Copyright (c) 2017 Simon Schmidt

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/


package digisig

import (
	"hash"
	"io"
	"math/big"
	"fmt"
)

type MAC func(key []byte) (hash.Hash, error)

// nil will result in "func(key []byte) []byte { return key }"
type Prek func(key []byte) []byte

type Signer struct{
	io.Writer
	mac hash.Hash
	t,x *big.Int
}

func NewSigner( priv *PrivateKey, mac MAC, prep Prek, ra io.Reader ) (*Signer,error) {
	s := new(Signer)
	temp := new(PrivateKey)
	*temp = *priv
	_,e := temp.Generate(ra)
	if e!=nil { return nil,e }
	s.t = temp.Secret
	s.x = priv.Secret
	
	r := temp.PublicKey().Public.Bytes()
	if prep!=nil { r = prep(r) }
	ho,e := mac(r)
	if e!=nil { return nil,e }
	s.mac = ho
	s.Writer = ho
	return s,nil
}
func (s *Signer) Sign() (E *big.Int,S *big.Int) {
	e := new(big.Int).SetBytes(s.mac.Sum(nil))
	xe := new(big.Int).Mul(e,s.x)
	sig := xe.Add(xe,s.t)
	return e,sig
}

type Verifier struct{
	io.Writer
	mac hash.Hash
	e *big.Int
}

func NewVerifier(E,S *big.Int, pub *PublicKey,mac MAC, prep Prek) (v *Verifier,err error) {
	defer func(){
		if ne := recover(); ne!=nil {
			err = fmt.Errorf("%v",ne)
		}
		if err!=nil { v = nil }
	}()
	v = new(Verifier)
	G := pub.Base()
	r := G.Exp(S).Mul(pub.Exp(E).ModInverse()).Public.Bytes()
	if prep!=nil { r = prep(r) }
	v.mac,err = mac(r)
	v.Writer = v.mac
	v.e = E
	return
}
func (v *Verifier) Verify() (*big.Int,bool) {
	e := new(big.Int).SetBytes(v.mac.Sum(nil))
	return e,e.Cmp(v.e)==0
}

