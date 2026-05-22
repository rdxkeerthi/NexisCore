package validator

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"sync"
	"time"
)

// NonceCache implements a thread-safe sliding-window nonce cache
type NonceCache struct {
	mu     sync.RWMutex
	nonces map[string]time.Time
	ttl    time.Duration
}

// NewNonceCache creates a new thread-safe sliding-window nonce cache
func NewNonceCache(ttl time.Duration, cleanupInterval time.Duration) *NonceCache {
	nc := &NonceCache{
		nonces: make(map[string]time.Time),
		ttl:    ttl,
	}
	go nc.startCleanup(cleanupInterval)
	return nc
}

// Register registers a nonce. If the nonce is already registered and within TTL, returns false.
func (nc *NonceCache) Register(nonce string) bool {
	if nonce == "" {
		return false
	}
	nc.mu.Lock()
	defer nc.mu.Unlock()

	now := time.Now()
	if exp, exists := nc.nonces[nonce]; exists && now.Before(exp) {
		return false // Replay attack detected
	}

	nc.nonces[nonce] = now.Add(nc.ttl)
	return true
}

func (nc *NonceCache) startCleanup(interval time.Duration) {
	ticker := time.NewTicker(interval)
	for range ticker.C {
		nc.mu.Lock()
		now := time.Now()
		for k, exp := range nc.nonces {
			if now.After(exp) {
				delete(nc.nonces, k)
			}
		}
		nc.mu.Unlock()
	}
}

// ProvenanceValidator validates incoming payload signatures and nonces
type ProvenanceValidator struct {
	pubKey     *ecdsa.PublicKey
	nonceCache *NonceCache
}

// NewProvenanceValidator parses the public key from the PEM file and initializes the validator
func NewProvenanceValidator(pemFilePath string, nonceTTL time.Duration) (*ProvenanceValidator, error) {
	pubKeyBytes, err := os.ReadFile(pemFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key PEM file: %w", err)
	}

	block, _ := pem.Decode(pubKeyBytes)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing public key")
	}

	// Parse PKIX public key
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKIX public key: %w", err)
	}

	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not an ECDSA public key")
	}

	return &ProvenanceValidator{
		pubKey:     ecdsaPub,
		nonceCache: NewNonceCache(nonceTTL, 1*time.Minute),
	}, nil
}

// ECDSASignature represents the ASN.1 unmarshalled R and S coordinates
type ECDSASignature struct {
	R, S *big.Int
}

// Verify checks the nonce and the cryptographic signature of the manifest payload
func (v *ProvenanceValidator) Verify(rawManifest []byte, hexSignature string, nonce string) error {
	// 1. Validate nonce
	if !v.nonceCache.Register(nonce) {
		return errors.New("nonce is invalid or has already been used within the TTL window")
	}

	// 2. Decode the hex-encoded signature string
	sigBytes, err := hex.DecodeString(hexSignature)
	if err != nil {
		return fmt.Errorf("failed to decode hex signature: %w", err)
	}

	// 3. Unpack R and S using ASN.1 unmarshalling
	var sig ECDSASignature
	rest, err := asn1.Unmarshal(sigBytes, &sig)
	if err != nil {
		return fmt.Errorf("failed to unmarshal ASN.1 signature: %w", err)
	}
	if len(rest) > 0 {
		return errors.New("extra bytes found after ASN.1 unmarshalling")
	}

	if sig.R == nil || sig.S == nil {
		return errors.New("invalid signature coordinates: R or S is nil")
	}

	// 4. Hash the raw manifest payload using SHA-256
	hash := sha256.Sum256(rawManifest)

	// 5. Verify the signature using ecdsa.Verify
	if !ecdsa.Verify(v.pubKey, hash[:], sig.R, sig.S) {
		return errors.New("cryptographic signature verification failed")
	}

	return nil
}
