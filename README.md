# digisig
Digital Signure Scheme

This is an implementation of the Schnorr signature based on Linear groups. For the linear groups, see RFC-3526.

https://godoc.org/github.com/mad-day/digisig

```go
package main

import "io"
import "fmt"
import "github.com/mad-day/digisig"

import "golang.org/x/crypto/sha3"

import "golang.org/x/crypto/blake2b"
import "github.com/mad-day/digisig/blake2butil"

func Message(f io.Writer) {
	fmt.Fprintln(f,"Hello World!")
	fmt.Fprintln(f,"Hello World!")
	fmt.Fprintln(f,"Hello World!")
	fmt.Fprintln(f,"Hello World!")
	fmt.Fprintln(f,"Hello World!")
	fmt.Fprintln(f,"Hello World!")
}

func Message2(f io.Writer) {
	fmt.Fprintln(f,"Hello World!")
	fmt.Fprintln(f,"Hello World!")
	fmt.Fprintln(f,"Hello World.")
	fmt.Fprintln(f,"Hello World!")
	fmt.Fprintln(f,"Hello World!")
	fmt.Fprintln(f,"Hello World!")
}

func main() {
	random := sha3.NewShake256()
	random.Write([]byte("12345"))
	pk,e := new(digisig.PrivateKey).SetGroup(digisig.Modp18).Generate(random)
	if e!=nil { fmt.Println(e); return }
	pub := pk.PublicKey()
	
	sig,e := digisig.NewSigner(pk,blake2b.New512,blake2butil.PreKey,random)
	if e!=nil { fmt.Println(e); return }
	
	Message(sig)
	E,S := sig.Sign()
	//fmt.Printf("E=%x\nS=%x\n",E,S)
	
	ver,e := digisig.NewVerifier(E,S,pub,blake2b.New512,blake2butil.PreKey)
	if e!=nil { fmt.Println(e); return }
	Message(ver)
	E2,ok := ver.Verify()
	
	fmt.Println()
	fmt.Println()
	fmt.Println()
	fmt.Printf("E=%x\nS=%x\n",E,S)
	fmt.Printf("E=%x\nok=%v\n",E2,ok)
	
	//fmt.Println(pk)
	//fmt.Println(pub)
}

```
