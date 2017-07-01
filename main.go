package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"

	"golang.org/x/crypto/acme"
	"golang.org/x/net/context/ctxhttp"
)

const baseAcctURL = "https://acme-v01.api.letsencrypt.org/acme/reg/"
const keyChangeURL = "https://acme-v01.api.letsencrypt.org/acme/key-change"

func main() {
	if len(os.Args) < 2 || os.Args[1] == "" {
		log.Fatal("You must specify an account number as the first argument.")
	}
	acctURL := baseAcctURL + os.Args[1]
	oldKey := getKeyFromFile("old.key")
	newKey := getKeyFromFile("new.key")
	jwkNew, err := jwkEncode(newKey.Public())
	if err != nil {
		log.Fatal(err)
	}
	innerPayload := map[string]interface{}{
		"account": acctURL,
		"newKey":  json.RawMessage(jwkNew),
	}
	innerJWS, err := jwsEncodeJSON(innerPayload, newKey, "")
	if err != nil {
		log.Fatal(err)
	}
	nonce, err := fetchNonce(context.Background(), http.DefaultClient, acctURL)
	if err != nil {
		log.Fatal(err)
	}
	innerJWS = []byte(string(innerJWS[:len(innerJWS)-1]) + `, "resource":"key-change"}`)
	outerJWS, err := jwsEncodeJSON(json.RawMessage(innerJWS), oldKey, nonce)
	if err != nil {
		log.Fatal(err)
	}

	JWKThumb, _ := acme.JWKThumbprint(newKey.Public())
	log.Println("Your new key's thumbprint for accepting ACME challenges is:", JWKThumb)
	log.Println("Please inspect the output below to see if LE accepted your new key.")
	resp, err := ctxhttp.Post(context.Background(), http.DefaultClient, keyChangeURL, "application/jose+json", bytes.NewReader(outerJWS))
	if err != nil {
		log.Println("HTTP Error:", err.Error())
		return
	}
	defer resp.Body.Close()
	log.Println("Status Code:", resp.StatusCode)
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println("ReadBody Error:", err.Error())
		return
	}
	log.Println("Body:", string(body))
}

func fetchNonce(ctx context.Context, client *http.Client, url string) (string, error) {
	resp, err := ctxhttp.Head(ctx, client, url)
	if err != nil {
		return "", nil
	}
	defer resp.Body.Close()
	enc := resp.Header.Get("replay-nonce")
	if enc == "" {
		return "", errors.New("acme: nonce not found")
	}
	return enc, nil
}

func jwsEncodeJSON(claimset interface{}, key crypto.Signer, nonce string) ([]byte, error) {
	jwk, err := jwkEncode(key.Public())
	if err != nil {
		return nil, err
	}
	alg, sha := jwsHasher(key)
	if alg == "" || !sha.Available() {
		return nil, errors.New("error")
	}
	phead := fmt.Sprintf(`{"alg":%q,"jwk":%s,"nonce":%q}`, alg, jwk, nonce)
	if nonce == "" {
		phead = fmt.Sprintf(`{"alg":%q,"jwk":%s}`, alg, jwk)
	}
	phead = base64.RawURLEncoding.EncodeToString([]byte(phead))
	cs, err := json.Marshal(claimset)
	if err != nil {
		return nil, err
	}
	payload := base64.RawURLEncoding.EncodeToString(cs)
	hash := sha.New()
	hash.Write([]byte(phead + "." + payload))
	sig, err := jwsSign(key, sha, hash.Sum(nil))
	if err != nil {
		return nil, err
	}

	enc := struct {
		Protected string `json:"protected"`
		Payload   string `json:"payload"`
		Sig       string `json:"signature"`
	}{
		Protected: phead,
		Payload:   payload,
		Sig:       base64.RawURLEncoding.EncodeToString(sig),
	}
	return json.Marshal(&enc)
}

func jwkEncode(pub crypto.PublicKey) (string, error) {
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		// https://tools.ietf.org/html/rfc7518#section-6.3.1
		n := pub.N
		e := big.NewInt(int64(pub.E))
		// Field order is important.
		// See https://tools.ietf.org/html/rfc7638#section-3.3 for details.
		return fmt.Sprintf(`{"e":"%s","kty":"RSA","n":"%s"}`,
			base64.RawURLEncoding.EncodeToString(e.Bytes()),
			base64.RawURLEncoding.EncodeToString(n.Bytes()),
		), nil
	case *ecdsa.PublicKey:
		// https://tools.ietf.org/html/rfc7518#section-6.2.1
		p := pub.Curve.Params()
		n := p.BitSize / 8
		if p.BitSize%8 != 0 {
			n++
		}
		x := pub.X.Bytes()
		if n > len(x) {
			x = append(make([]byte, n-len(x)), x...)
		}
		y := pub.Y.Bytes()
		if n > len(y) {
			y = append(make([]byte, n-len(y)), y...)
		}
		// Field order is important.
		// See https://tools.ietf.org/html/rfc7638#section-3.3 for details.
		return fmt.Sprintf(`{"crv":"%s","kty":"EC","x":"%s","y":"%s"}`,
			p.Name,
			base64.RawURLEncoding.EncodeToString(x),
			base64.RawURLEncoding.EncodeToString(y),
		), nil
	}
	return "", errors.New("error")
}

func jwsSign(key crypto.Signer, hash crypto.Hash, digest []byte) ([]byte, error) {
	switch key := key.(type) {
	case *rsa.PrivateKey:
		return key.Sign(rand.Reader, digest, hash)
	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, key, digest)
		if err != nil {
			return nil, err
		}
		rb, sb := r.Bytes(), s.Bytes()
		size := key.Params().BitSize / 8
		if size%8 > 0 {
			size++
		}
		sig := make([]byte, size*2)
		copy(sig[size-len(rb):], rb)
		copy(sig[size*2-len(sb):], sb)
		return sig, nil
	}
	return nil, errors.New("error")
}

func jwsHasher(key crypto.Signer) (string, crypto.Hash) {
	switch key := key.(type) {
	case *rsa.PrivateKey:
		return "RS256", crypto.SHA256
	case *ecdsa.PrivateKey:
		switch key.Params().Name {
		case "P-256":
			return "ES256", crypto.SHA256
		case "P-384":
			return "ES384", crypto.SHA384
		case "P-512":
			return "ES512", crypto.SHA512
		}
	}
	return "", 0
}

func getKeyFromFile(filename string) crypto.Signer {
	keyPEMBlock, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}
	keyDERBlock, _ := pem.Decode(keyPEMBlock)
	key, err := x509.ParsePKCS1PrivateKey(keyDERBlock.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	return key
}
