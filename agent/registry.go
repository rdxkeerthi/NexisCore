// Package agent implements multi-agent identity management for NexisCore.
//
// Each agent receives:
//   - A cryptographically unique UUID (AgentID)
//   - An Ed25519 key pair for signing and mTLS
//   - A SPIFFE-format URI: spiffe://nexiscore.local/agent/<uuid>
//   - A self-signed X.509 certificate (valid 24h, auto-renewable) for TLS
//
// The AgentRegistry is the authoritative source for agent identity lookup
// and is safe for concurrent access.
package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"sync"
	"time"

	"github.com/google/uuid"
)

// spiffeTrustDomain is the SPIFFE trust domain for all NexisCore agents.
const spiffeTrustDomain = "nexiscore.local"

// AgentIdentity holds the full cryptographic identity of a registered agent.
type AgentIdentity struct {
	// AgentID is the unique UUID string for this agent.
	AgentID string
	// SPIFFEID is the SPIFFE URI: spiffe://nexiscore.local/agent/<AgentID>
	SPIFFEID string
	// PublicKey is the Ed25519 public key for signature verification.
	PublicKey ed25519.PublicKey
	// privateKey is unexported: only the agent itself may sign.
	privateKey ed25519.PrivateKey
	// TLSCert is the mTLS certificate for inter-agent connections.
	TLSCert tls.Certificate
	// CertDER is the raw DER-encoded certificate for distribution.
	CertDER []byte
	// RegisteredAt is the UTC timestamp of registration.
	RegisteredAt time.Time
	// ExpiresAt is the certificate expiry timestamp.
	ExpiresAt time.Time
	// Metadata is an arbitrary key-value store for agent annotations.
	Metadata map[string]string
}

// Sign signs the given message using the agent's Ed25519 private key.
func (a *AgentIdentity) Sign(message []byte) ([]byte, error) {
	if a.privateKey == nil {
		return nil, errors.New("agent: private key unavailable")
	}
	sig := ed25519.Sign(a.privateKey, message)
	return sig, nil
}

// Verify checks a signature against the agent's Ed25519 public key.
func (a *AgentIdentity) Verify(message, sig []byte) bool {
	return ed25519.Verify(a.PublicKey, message, sig)
}

// TLSConfig returns a *tls.Config suitable for use as a mTLS client or server.
// certPool should contain the peer's certificate for mutual verification.
func (a *AgentIdentity) TLSConfig(certPool *x509.CertPool) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{a.TLSCert},
		ClientCAs:    certPool,
		RootCAs:      certPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
		// Enforce SPIFFE SAN verification via VerifyPeerCertificate
		VerifyPeerCertificate: makeSPIFFEVerifier(spiffeTrustDomain),
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Certificate generation
// ─────────────────────────────────────────────────────────────────────────────

// newAgentIdentity generates a fresh AgentIdentity with Ed25519 keys and a
// self-signed X.509 certificate embedding the SPIFFE URI as a SAN.
func newAgentIdentity(metadata map[string]string) (*AgentIdentity, error) {
	// 1. Generate Ed25519 key pair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("agent: key generation failed: %w", err)
	}

	// 2. Generate UUID and SPIFFE ID
	agentID := uuid.New().String()
	spiffeID := fmt.Sprintf("spiffe://%s/agent/%s", spiffeTrustDomain, agentID)

	spiffeURI, err := url.Parse(spiffeID)
	if err != nil {
		return nil, fmt.Errorf("agent: invalid SPIFFE URI: %w", err)
	}

	now := time.Now().UTC()
	expiry := now.Add(24 * time.Hour)

	// 3. Build X.509 certificate template with SPIFFE SAN
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("agent: serial number generation failed: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   agentID,
			Organization: []string{"NexisCore"},
		},
		URIs:                  []*url.URL{spiffeURI},
		NotBefore:             now,
		NotAfter:              expiry,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// 4. Self-sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		return nil, fmt.Errorf("agent: certificate creation failed: %w", err)
	}

	// 5. Assemble tls.Certificate
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	privPEMBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("agent: private key marshal failed: %w", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privPEMBytes})

	tlsCert, err := tls.X509KeyPair(certPEM, privPEM)
	if err != nil {
		return nil, fmt.Errorf("agent: tls.X509KeyPair failed: %w", err)
	}

	if metadata == nil {
		metadata = make(map[string]string)
	}

	return &AgentIdentity{
		AgentID:      agentID,
		SPIFFEID:     spiffeID,
		PublicKey:    pub,
		privateKey:   priv,
		TLSCert:      tlsCert,
		CertDER:      certDER,
		RegisteredAt: now,
		ExpiresAt:    expiry,
		Metadata:     metadata,
	}, nil
}

// makeSPIFFEVerifier returns a VerifyPeerCertificate function that enforces
// that the peer presents a certificate with a SPIFFE URI SAN in our trust domain.
func makeSPIFFEVerifier(trustDomain string) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("agent/mtls: peer provided no certificate")
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("agent/mtls: failed parsing peer certificate: %w", err)
		}
		for _, uri := range cert.URIs {
			if uri.Scheme == "spiffe" && uri.Host == trustDomain {
				return nil
			}
		}
		return fmt.Errorf("agent/mtls: peer certificate has no valid SPIFFE URI in trust domain %q", trustDomain)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// AgentRegistry
// ─────────────────────────────────────────────────────────────────────────────

// AgentRegistry is the authoritative, thread-safe registry of all active agent
// identities in the NexisCore cluster.
type AgentRegistry struct {
	mu      sync.RWMutex
	agents  map[string]*AgentIdentity // keyed by AgentID
	bySpiffe map[string]*AgentIdentity // keyed by SPIFFE ID
}

// NewAgentRegistry creates an empty, ready-to-use registry.
func NewAgentRegistry() *AgentRegistry {
	return &AgentRegistry{
		agents:   make(map[string]*AgentIdentity),
		bySpiffe: make(map[string]*AgentIdentity),
	}
}

// Register allocates a fresh cryptographic identity, stores it in the registry,
// and returns the new AgentIdentity. metadata is optional.
func (r *AgentRegistry) Register(metadata map[string]string) (*AgentIdentity, error) {
	identity, err := newAgentIdentity(metadata)
	if err != nil {
		return nil, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.agents[identity.AgentID] = identity
	r.bySpiffe[identity.SPIFFEID] = identity
	return identity, nil
}

// Lookup returns the identity for the given AgentID. Returns nil if not found.
func (r *AgentRegistry) Lookup(agentID string) *AgentIdentity {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.agents[agentID]
}

// LookupBySPIFFE returns the identity for the given SPIFFE URI. Returns nil if not found.
func (r *AgentRegistry) LookupBySPIFFE(spiffeID string) *AgentIdentity {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.bySpiffe[spiffeID]
}

// Deregister removes an agent from the registry. Returns an error if the
// agent was not registered.
func (r *AgentRegistry) Deregister(agentID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	identity, ok := r.agents[agentID]
	if !ok {
		return fmt.Errorf("agent: %q not found in registry", agentID)
	}
	delete(r.agents, agentID)
	delete(r.bySpiffe, identity.SPIFFEID)
	return nil
}

// ListActive returns a snapshot of all currently registered agent identities.
func (r *AgentRegistry) ListActive() []*AgentIdentity {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*AgentIdentity, 0, len(r.agents))
	for _, id := range r.agents {
		out = append(out, id)
	}
	return out
}

// Count returns the number of registered agents.
func (r *AgentRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.agents)
}

// BuildCertPool creates an *x509.CertPool containing all currently registered
// agent certificates. Used to configure mTLS peer verification.
func (r *AgentRegistry) BuildCertPool() *x509.CertPool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	pool := x509.NewCertPool()
	for _, id := range r.agents {
		cert, err := x509.ParseCertificate(id.CertDER)
		if err == nil {
			pool.AddCert(cert)
		}
	}
	return pool
}

// PruneExpired removes any agents whose certificates have expired. Returns the
// count of agents pruned.
func (r *AgentRegistry) PruneExpired() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now().UTC()
	pruned := 0
	for id, identity := range r.agents {
		if now.After(identity.ExpiresAt) {
			delete(r.agents, id)
			delete(r.bySpiffe, identity.SPIFFEID)
			pruned++
		}
	}
	return pruned
}
