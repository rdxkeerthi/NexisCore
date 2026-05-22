package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"
)

// ECDSASignature represents the ASN.1 structure for an ECDSA signature
type ECDSASignature struct {
	R, S *big.Int
}

func main() {
	fmt.Println("=== NexisCore Key and Signature Generator ===")

	// 1. Generate P-256 ECDSA Key Pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	// 2. Encode and write Private Key PEM
	privBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		log.Fatalf("Failed to marshal private key: %v", err)
	}
	privPemFile, err := os.Create("private_key.pem")
	if err != nil {
		log.Fatalf("Failed to create private_key.pem: %v", err)
	}
	defer privPemFile.Close()

	err = pem.Encode(privPemFile, &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privBytes,
	})
	if err != nil {
		log.Fatalf("Failed to write private key PEM: %v", err)
	}
	fmt.Println("[+] Successfully generated private_key.pem")

	// 3. Encode and write Public Key PEM
	pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		log.Fatalf("Failed to marshal public key: %v", err)
	}
	pubPemFile, err := os.Create("public_key.pem")
	if err != nil {
		log.Fatalf("Failed to create public_key.pem: %v", err)
	}
	defer pubPemFile.Close()

	err = pem.Encode(pubPemFile, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})
	if err != nil {
		log.Fatalf("Failed to write public key PEM: %v", err)
	}
	fmt.Println("[+] Successfully generated public_key.pem")

	// 4. Create a sample manifest payload
	nonce := fmt.Sprintf("nonce_%d", time.Now().UnixNano())
	manifestData := map[string]interface{}{
		"tool_name": "python_interpreter",
		"nonce":     nonce,
		"timestamp": time.Now().Unix(),
	}

	manifestBytes, err := json.Marshal(manifestData)
	if err != nil {
		log.Fatalf("Failed to marshal manifest: %v", err)
	}
	manifestString := string(manifestBytes)

	// 5. Hash the manifest payload using SHA-256
	hash := sha256.Sum256(manifestBytes)

	// 6. Sign the hash using ECDSA Private Key
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		log.Fatalf("Failed to sign manifest hash: %v", err)
	}

	// 7. Marshal to ASN.1 DER format
	sigStruct := ECDSASignature{R: r, S: s}
	sigBytes, err := asn1.Marshal(sigStruct)
	if err != nil {
		log.Fatalf("Failed to marshal signature to ASN.1: %v", err)
	}
	hexSignature := hex.EncodeToString(sigBytes)

	// 8. Output signature block and curl instructions
	fmt.Println("\n=== Generated Test Payload details ===")
	fmt.Printf("Raw Manifest:\n%s\n\n", manifestString)
	fmt.Printf("Nonce:\n%s\n\n", nonce)
	fmt.Printf("Signature (Hex):\n%s\n\n", hexSignature)

	fmt.Println("=== Example Intercept Request JSON ===")
	requestPayload := map[string]interface{}{
		"script":    "print('Hello from sandboxed runtime!')",
		"variables": map[string]interface{}{"param1": []interface{}{"val1", "val2"}},
		"manifest":  manifestString,
		"signature": hexSignature,
	}
	requestJson, _ := json.MarshalIndent(requestPayload, "", "  ")
	fmt.Println(string(requestJson))

	// Save request json as a test file
	err = os.WriteFile("test_payload.json", requestJson, 0644)
	if err == nil {
		fmt.Println("\n[+] Created 'test_payload.json' for testing!")
	}
}
