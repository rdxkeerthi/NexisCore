package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
)

func main() {
	// We expect the JSON manifest as the first command-line argument
	if len(os.Args) < 2 {
		log.Fatalf("Usage: go run tools/signer.go '<json_manifest>'")
	}
	rawManifest := os.Args[1]

	// 1. Read private key from `./certs/private.pem`
	privBytes, err := os.ReadFile("./certs/private.pem")
	if err != nil {
		log.Fatalf("Failed to read private key file ./certs/private.pem: %v", err)
	}

	block, _ := pem.Decode(privBytes)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		log.Fatalf("Failed to decode PEM block containing EC PRIVATE KEY")
	}

	// 2. Parse private key
	privKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse EC Private Key: %v", err)
	}

	// 3. Hash the raw manifest JSON byte stream via SHA-256
	hash := sha256.Sum256([]byte(rawManifest))

	// 4. Sign the hash using ecdsa.SignASN1 (cryptographic token stream)
	sigBytes, err := ecdsa.SignASN1(rand.Reader, privKey, hash[:])
	if err != nil {
		log.Fatalf("Failed to sign manifest hash block: %v", err)
	}

	// 5. Output the signature as a hex-encoded string directly to stdout
	hexSignature := hex.EncodeToString(sigBytes)
	fmt.Print(hexSignature)
}

// SignManifestHelper is a helper function used programmatically in integration tests
func SignManifestHelper(rawManifest string, privateKeyPEM []byte) (string, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return "", errors.New("failed to decode private key PEM")
	}

	privKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		// Fallback PKCS#8 parsing if generated differently
		pub, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return "", err
		}
		var ok bool
		privKey, ok = pub.(*ecdsa.PrivateKey)
		if !ok {
			return "", errors.New("not an ECDSA private key")
		}
	}

	hash := sha256.Sum256([]byte(rawManifest))
	sigBytes, err := ecdsa.SignASN1(rand.Reader, privKey, hash[:])
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(sigBytes), nil
}
