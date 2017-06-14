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

import "math/big"
import "crypto/rand"
import "fmt"
import "io"

const (
	Modp5 = 5   /* 1536-bit MODP Group */
	Modp14 = 14 /* 2048-bit MODP Group */
	Modp15 = 15 /* 3072-bit MODP Group */
	Modp16 = 16 /* 4096-bit MODP Group */
	Modp17 = 17 /* 6144-bit MODP Group */
	Modp18 = 18 /* 8192-bit MODP Group */
)

type PrivateKey struct {
	Group int
	Secret *big.Int
}

type PublicKey struct {
	Group int
	Public *big.Int
}

func (p *PrivateKey) PublicKey() *PublicKey {
	g,ok := linearGroups[p.Group]
	if !ok { panic(fmt.Sprint("No such group: ",p.Group)) }
	return &PublicKey{p.Group,new(big.Int).Exp(g.G,p.Secret,g.P)}
}

func (p *PrivateKey) SetGroup(g int) *PrivateKey {
	p.Group = g
	return p
}

func (p *PrivateKey) Generate(r io.Reader) (*PrivateKey,error) {
	g,ok := linearGroups[p.Group]
	if !ok { return nil,fmt.Errorf("No such group: %v",p.Group) }
	
	raw := make([]byte,(g.Ez+7)>>3)
	n,e := r.Read(raw)
	if e!=nil { return nil,e }
	if n<len(raw) { raw = raw[:n] }
	p.Secret,e = rand.Int(r,new(big.Int).SetBytes(raw))
	if e!=nil { return nil,e }
	return p,nil
}
func (p *PrivateKey) String() string {
	return fmt.Sprintf("Modp%d-SECRET:%x",p.Group,p.Secret)
}

/* --------------------------------------------------------------------------------------------- */

func (p *PublicKey) Base() *PublicKey {
	g,ok := linearGroups[p.Group]
	if !ok { panic(fmt.Sprint("No such group: ",p.Group)) }
	return &PublicKey{p.Group,new(big.Int).Set(g.G) /* Get a Copy of G; safety first! */ }
}

func (p *PublicKey) Exp(i *big.Int) *PublicKey {
	g,ok := linearGroups[p.Group]
	if !ok { panic(fmt.Sprint("No such group: ",p.Group)) }
	return &PublicKey{p.Group,new(big.Int).Exp(p.Public,i,g.P)}
}

func (p *PublicKey) ModInverse() *PublicKey {
	g,ok := linearGroups[p.Group]
	if !ok { panic(fmt.Sprint("No such group: ",p.Group)) }
	return &PublicKey{p.Group,new(big.Int).ModInverse(p.Public,g.P)}
}

func (p *PublicKey) Mul(o *PublicKey) *PublicKey {
	if o.Group!=p.Group { panic(fmt.Sprint("Cant multiply from different groups: ",o.Group,"!=",p.Group)) }
	g,ok := linearGroups[p.Group]
	if !ok { panic(fmt.Sprint("No such group: ",p.Group)) }
	m := new(big.Int).Mul(p.Public,o.Public)
	return &PublicKey{p.Group,m.Mod(m,g.P)}
}

func (p *PublicKey) String() string {
	return fmt.Sprintf("Modp%d-PUBLIC:%x",p.Group,p.Public)
}


