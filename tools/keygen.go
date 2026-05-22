package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

func main() {
	fmt.Println("=== NexisCore Enclave Key Generator ===")

	// 1. Establish certs directory with secure 0700 permissions
	certsDir := "./certs"
	err := os.MkdirAll(certsDir, 0700)
	if err != nil {
		log.Fatalf("Failed to create certs directory: %v", err)
	}

	// 2. Generate P-256 ECDSA Key Pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate P-256 private key: %v", err)
	}

	// 3. Marshal and encode Private Key block
	privBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		log.Fatalf("Failed to marshal private key bytes: %v", err)
	}

	privPem := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privBytes,
	})

	privPath := filepath.Join(certsDir, "private.pem")
	err = os.WriteFile(privPath, privPem, 0600)
	if err != nil {
		log.Fatalf("Failed to write private.pem to filesystem: %v", err)
	}
	fmt.Printf("[+] Saved private key block to %s\n", privPath)

	// 4. Marshal and encode Public Key block
	pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		log.Fatalf("Failed to marshal public key bytes: %v", err)
	}

	pubPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})

	pubPath := filepath.Join(certsDir, "public.pem")
	err = os.WriteFile(pubPath, pubPem, 0644)
	if err != nil {
		log.Fatalf("Failed to write public.pem to filesystem: %v", err)
	}
	fmt.Printf("[+] Saved public key block to %s\n", pubPath)

	fmt.Println("[SUCCESS] Enclave PKI Key pair successfully generated under ./certs")
}
