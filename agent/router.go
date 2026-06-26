// Package agent — AgentRouter: in-process mTLS virtual routing layer.
//
// The router mediates ALL inter-agent context exchange. For each routing request:
//  1. ACL check via PolicyManager — deny if not explicitly permitted.
//  2. mTLS handshake using net.Pipe() + crypto/tls — both ends authenticate.
//  3. Payload is encrypted in transit (TLS 1.3) even for in-process pipes.
//  4. Both route allow and deny decisions are emitted as OCSF events.
//
// RouteContext() is synchronous from the caller's perspective and returns
// the decrypted response payload from the destination agent's handler.
package agent

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"nexiscore/telemetry"
)

// RouteHandler is the function signature for an agent's message handler.
// It receives the decrypted payload from the sender and returns a response payload.
type RouteHandler func(fromAgentID string, payload []byte) ([]byte, error)

// AgentRouter manages in-process mTLS channel creation between agents.
type AgentRouter struct {
	registry *AgentRegistry
	policy   *PolicyManager
	handlers map[string]RouteHandler // keyed by AgentID
	mu       sync.RWMutex
}

// NewAgentRouter creates a new AgentRouter backed by the given registry and policy.
func NewAgentRouter(registry *AgentRegistry, policy *PolicyManager) *AgentRouter {
	return &AgentRouter{
		registry: registry,
		policy:   policy,
		handlers: make(map[string]RouteHandler),
	}
}

// RegisterHandler registers the message handler for a given agent. The handler
// is invoked when another agent sends a routed payload to agentID.
func (r *AgentRouter) RegisterHandler(agentID string, handler RouteHandler) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.handlers[agentID] = handler
}

// RouteContext routes a payload from fromAgent to toAgent through a full mTLS
// handshake. It enforces the ACL policy and emits OCSF telemetry for every
// routing decision. Returns the response payload from the destination handler.
func (r *AgentRouter) RouteContext(fromAgentID, toAgentID string, payload []byte) ([]byte, error) {
	// 1. Resolve identities from registry
	fromAgent := r.registry.Lookup(fromAgentID)
	if fromAgent == nil {
		return nil, fmt.Errorf("router: sender agent %q not registered", fromAgentID)
	}
	toAgent := r.registry.Lookup(toAgentID)
	if toAgent == nil {
		return nil, fmt.Errorf("router: destination agent %q not registered", toAgentID)
	}

	// 2. ACL check
	if !r.policy.IsRoutePermitted(fromAgent.SPIFFEID, toAgent.SPIFFEID) {
		reason := fmt.Sprintf("route %s → %s denied by ACL policy", fromAgent.SPIFFEID, toAgent.SPIFFEID)
		log.Printf("[ROUTER] DENY: %s", reason)
		telemetry.SubmitGlobal(telemetry.NewAgentRouteEvent(fromAgentID, toAgentID, false, reason))
		return nil, fmt.Errorf("router: %s", reason)
	}

	// 3. Locate destination handler
	r.mu.RLock()
	handler, ok := r.handlers[toAgentID]
	r.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("router: no handler registered for agent %q", toAgentID)
	}

	// 4. Build a shared cert pool containing both agents' certs
	certPool := x509.NewCertPool()
	fromCert, err := x509.ParseCertificate(fromAgent.CertDER)
	if err != nil {
		return nil, fmt.Errorf("router: failed parsing from-agent cert: %w", err)
	}
	toCert, err := x509.ParseCertificate(toAgent.CertDER)
	if err != nil {
		return nil, fmt.Errorf("router: failed parsing to-agent cert: %w", err)
	}
	certPool.AddCert(fromCert)
	certPool.AddCert(toCert)

	// 5. Create an in-process net.Pipe (zero network overhead)
	serverConn, clientConn := net.Pipe()

	var (
		routeErr    error
		response    []byte
		handlerDone = make(chan struct{})
	)

	// 6. Server goroutine: performs TLS server handshake and dispatches to handler
	go func() {
		defer close(handlerDone)
		defer serverConn.Close()

		serverTLSCfg := &tls.Config{
			Certificates: []tls.Certificate{toAgent.TLSCert},
			ClientCAs:    certPool,
			ClientAuth:   tls.RequireAndVerifyClientCert,
			MinVersion:   tls.VersionTLS13,
			VerifyPeerCertificate: makeSPIFFEVerifier(spiffeTrustDomain),
		}

		tlsServer := tls.Server(serverConn, serverTLSCfg)
		if err := tlsServer.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			routeErr = fmt.Errorf("router: server deadline set failed: %w", err)
			return
		}
		if err := tlsServer.Handshake(); err != nil {
			routeErr = fmt.Errorf("router: mTLS server handshake failed: %w", err)
			return
		}

		// Read the payload from the TLS connection
		incoming, err := io.ReadAll(io.LimitReader(tlsServer, 1<<20)) // 1 MiB limit
		if err != nil {
			routeErr = fmt.Errorf("router: server read failed: %w", err)
			return
		}

		// Dispatch to registered handler
		resp, handlerErr := handler(fromAgentID, incoming)
		if handlerErr != nil {
			routeErr = fmt.Errorf("router: handler error: %w", handlerErr)
			return
		}

		// Write response back through TLS pipe
		if _, err := tlsServer.Write(resp); err != nil {
			routeErr = fmt.Errorf("router: server write failed: %w", err)
			return
		}
		response = resp
	}()

	// 7. Client side: performs TLS client handshake and sends payload
	func() {
		defer clientConn.Close()

		clientTLSCfg := &tls.Config{
			Certificates: []tls.Certificate{fromAgent.TLSCert},
			RootCAs:      certPool,
			ServerName:   toAgentID,
			MinVersion:   tls.VersionTLS13,
			// We use VerifyPeerCertificate because ServerName won't match SPIFFE URI SANs
			InsecureSkipVerify:    true, //nolint:gosec — we verify via VerifyPeerCertificate below
			VerifyPeerCertificate: makeSPIFFEVerifier(spiffeTrustDomain),
		}

		tlsClient := tls.Client(clientConn, clientTLSCfg)
		if err := tlsClient.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			routeErr = fmt.Errorf("router: client deadline set failed: %w", err)
			return
		}
		if err := tlsClient.Handshake(); err != nil {
			routeErr = fmt.Errorf("router: mTLS client handshake failed: %w", err)
			return
		}

		// Write payload
		if _, err := tlsClient.Write(payload); err != nil {
			routeErr = fmt.Errorf("router: client write failed: %w", err)
			return
		}
		// Signal EOF to server so it can read the full payload
		_ = tlsClient.CloseWrite()

		// Read response
		resp, err := io.ReadAll(io.LimitReader(tlsClient, 1<<20))
		if err != nil && !errors.Is(err, io.EOF) {
			routeErr = fmt.Errorf("router: client read response failed: %w", err)
			return
		}
		response = resp
	}()

	// 8. Wait for handler goroutine to finish
	<-handlerDone

	if routeErr != nil {
		telemetry.SubmitGlobal(telemetry.NewAgentRouteEvent(fromAgentID, toAgentID, false, routeErr.Error()))
		return nil, routeErr
	}

	// 9. Emit success telemetry
	successReason := fmt.Sprintf("mTLS context exchange %s → %s succeeded (%d bytes)",
		fromAgent.SPIFFEID, toAgent.SPIFFEID, len(payload))
	log.Printf("[ROUTER] ALLOW: %s", successReason)
	telemetry.SubmitGlobal(telemetry.NewAgentRouteEvent(fromAgentID, toAgentID, true, successReason))

	return response, nil
}
