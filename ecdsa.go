package signature

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
)

type ECDSASignature struct {
	R, S *big.Int
}

var (
	// curveHalfOrders contains the precomputed curve group orders halved.
	// It is used to ensure that signature' S value is lower or equal to the
	// curve group order halved. We accept only low-S signatures.
	// They are precomputed for efficiency reasons.
	curveHalfOrders = map[elliptic.Curve]*big.Int{
		elliptic.P224(): new(big.Int).Rsh(elliptic.P224().Params().N, 1),
		elliptic.P256(): new(big.Int).Rsh(elliptic.P256().Params().N, 1),
		elliptic.P384(): new(big.Int).Rsh(elliptic.P384().Params().N, 1),
		elliptic.P521(): new(big.Int).Rsh(elliptic.P521().Params().N, 1),
	}
)

func SignECDSA(content string, privateKeyStr string) (string, error) {
	priKey, e := genPKCSpec(privateKeyStr)
	if e != nil {
		return "", e
	}

	// 转换为 256hash
	digest := hash(content)
	si, _ := signWithECDSA(priKey, digest)
	sign := base64.RawURLEncoding.EncodeToString(si)
	return sign, nil
}

func signWithECDSA(k *ecdsa.PrivateKey, digest []byte) (signature []byte, err error) {
	r, s, err := ecdsa.Sign(rand.Reader, k, digest)
	if err != nil {
		return nil, err
	}

	s, _, err = toLowS(&k.PublicKey, s)
	if err != nil {
		return nil, err
	}

	return marshalECDSASignature(r, s)
}

func genPKCSpec(privateKeyStr string) (*ecdsa.PrivateKey, error) {
	bytes, err := base64.RawURLEncoding.DecodeString(privateKeyStr)
	if err != nil {
		return nil, err
	}

	key, err := x509.ParsePKCS8PrivateKey(bytes)
	if err != nil {
		return nil, errors.New("failed to parse private key from PrivateKey")
	}
	return key.(*ecdsa.PrivateKey), nil
}

func marshalECDSASignature(r, s *big.Int) ([]byte, error) {
	return asn1.Marshal(ECDSASignature{r, s})
}

func hash(data string) []byte {
	bmsg := []byte(data)

	h := sha256.New()
	h.Write([]byte(bmsg))
	hash := h.Sum(nil)
	return hash
}

// IsLow checks that s is a low-S
func isLowS(k *ecdsa.PublicKey, s *big.Int) (bool, error) {
	halfOrder, ok := curveHalfOrders[k.Curve]
	if !ok {
		return false, fmt.Errorf("curve not recognized [%s]", k.Curve)
	}

	return s.Cmp(halfOrder) != 1, nil

}

func toLowS(k *ecdsa.PublicKey, s *big.Int) (*big.Int, bool, error) {
	lowS, err := isLowS(k, s)
	if err != nil {
		return nil, false, err
	}

	if !lowS {
		// Set s to N - s that will be then in the lower part of signature space
		// less or equal to half order
		s.Sub(k.Params().N, s)

		return s, true, nil
	}

	return s, false, nil
}
