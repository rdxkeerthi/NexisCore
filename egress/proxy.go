// Package egress — EgressProxy: http.RoundTripper that intercepts all outbound
// requests and enforces allowlist routing, DLP scrubbing, and payload attestation.
//
// Every outbound request goes through 5 stages:
//  1. Allowlist check: reject if destination host/IP not in approved list.
//  2. Body buffering: read the full request body for inspection.
//  3. DLP scrubbing: redact sensitive patterns from the buffered body.
//  4. Payload attestation: ECDSA-sign the SHA-256 of the scrubbed body.
//     The signature is attached as X-NexisCore-Payload-Sig header.
//  5. Forward: send the sanitised request to the real destination.
//
// OCSF telemetry events are emitted for every block, DLP hit, and successful dispatch.
package egress

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync/atomic"
	"time"

	"nexiscore/telemetry"
)

// EgressProxy implements http.RoundTripper. Wrap an *http.Client with it by
// setting client.Transport = proxy.
type EgressProxy struct {
	allowlist *AllowlistRouter
	dlp       *DLPPipeline
	signer    *ecdsa.PrivateKey // may be nil; signing skipped if nil
	agentID   string
	inner     http.RoundTripper

	// Atomic metrics
	requestsAllowed int64
	requestsBlocked int64
	dlpFindings     int64
}

// NewEgressProxy constructs a proxy. signer may be nil to skip payload attestation.
// agentID is used in OCSF telemetry events.
func NewEgressProxy(
	allowlist *AllowlistRouter,
	dlp *DLPPipeline,
	signer *ecdsa.PrivateKey,
	agentID string,
) *EgressProxy {
	return &EgressProxy{
		allowlist: allowlist,
		dlp:       dlp,
		signer:    signer,
		agentID:   agentID,
		inner:     http.DefaultTransport,
	}
}

// NewEgressClient returns an *http.Client pre-configured with the EgressProxy
// as its transport.
func NewEgressClient(
	allowlist *AllowlistRouter,
	dlp *DLPPipeline,
	signer *ecdsa.PrivateKey,
	agentID string,
) *http.Client {
	proxy := NewEgressProxy(allowlist, dlp, signer, agentID)
	return &http.Client{
		Transport: proxy,
		Timeout:   30 * time.Second,
	}
}

// RoundTrip executes the 5-stage egress pipeline and returns the upstream response.
// It satisfies the http.RoundTripper interface.
func (p *EgressProxy) RoundTrip(req *http.Request) (*http.Response, error) {
	host := req.URL.Hostname()
	destination := req.URL.Host
	if destination == "" {
		destination = host
	}

	// ── Stage 1: Allowlist check ──────────────────────────────────────────────
	if !p.allowlist.IsAllowed(host) {
		atomic.AddInt64(&p.requestsBlocked, 1)
		reason := fmt.Sprintf("destination %q not in egress allowlist", destination)
		log.Printf("[EGRESS] BLOCK: %s", reason)
		telemetry.SubmitGlobal(telemetry.NewEgressBlockEvent(p.agentID, destination, reason))
		return nil, fmt.Errorf("egress: %s", reason)
	}

	// ── Stage 2: Buffer request body ─────────────────────────────────────────
	var bodyBytes []byte
	if req.Body != nil && req.Body != http.NoBody {
		var err error
		bodyBytes, err = io.ReadAll(io.LimitReader(req.Body, 10<<20)) // 10 MiB cap
		if err != nil {
			return nil, fmt.Errorf("egress: failed reading request body: %w", err)
		}
		_ = req.Body.Close()
	}

	// ── Stage 3: DLP scrubbing ───────────────────────────────────────────────
	var findings []DLPFinding
	var dlpErr error
	if len(bodyBytes) > 0 {
		bodyBytes, findings, dlpErr = p.dlp.Scrub(bodyBytes)
		if dlpErr != nil {
			return nil, fmt.Errorf("egress: DLP scrub failed: %w", dlpErr)
		}
	}

	if ContainsFindings(findings) {
		atomic.AddInt64(&p.dlpFindings, int64(len(findings)))
		summary := RedactionSummary(findings)
		log.Printf("[EGRESS][DLP] Redacted %d finding(s) in payload to %s: %s",
			len(findings), destination, summary)
		telemetry.SubmitGlobal(telemetry.NewDLPFindingEvent(
			p.agentID,
			destination,
			len(findings),
			UniquePatternNames(findings),
		))
	}

	// ── Stage 4: Payload attestation ─────────────────────────────────────────
	// Compute SHA-256 of the (potentially scrubbed) body and ECDSA-sign it.
	// The signature proves the payload was processed by the NexisCore DLP pipeline.
	var sigHex string
	if p.signer != nil && len(bodyBytes) > 0 {
		hash := sha256.Sum256(bodyBytes)
		sigBytes, err := ecdsa.SignASN1(rand.Reader, p.signer, hash[:])
		if err != nil {
			return nil, fmt.Errorf("egress: payload attestation signing failed: %w", err)
		}
		sigHex = hex.EncodeToString(sigBytes)
		log.Printf("[EGRESS] Payload attested → sha256:%s sig:%s...", hex.EncodeToString(hash[:8]), sigHex[:16])
	}

	// ── Stage 5: Reconstruct and forward ─────────────────────────────────────
	// Clone the request so we don't mutate the caller's object
	outReq := req.Clone(req.Context())
	if len(bodyBytes) > 0 {
		outReq.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		outReq.ContentLength = int64(len(bodyBytes))
	} else {
		outReq.Body = http.NoBody
		outReq.ContentLength = 0
	}

	// Attach attestation headers
	if sigHex != "" {
		outReq.Header.Set("X-NexisCore-Payload-Sig", sigHex)
		outReq.Header.Set("X-NexisCore-DLP-Version", "1.0")
		outReq.Header.Set("X-NexisCore-Agent-ID", p.agentID)
	}
	if len(findings) > 0 {
		outReq.Header.Set("X-NexisCore-DLP-Redactions", fmt.Sprintf("%d", len(findings)))
	}

	resp, err := p.inner.RoundTrip(outReq)
	if err != nil {
		log.Printf("[EGRESS] Forward to %s failed: %v", destination, err)
		telemetry.SubmitGlobal(telemetry.NewToolCallEvent(
			p.agentID, "egress_proxy", destination,
			telemetry.StatusFailure,
			fmt.Sprintf("forward failed: %v", err),
		))
		return nil, err
	}

	atomic.AddInt64(&p.requestsAllowed, 1)
	log.Printf("[EGRESS] → %s %s [HTTP %d] dlp_findings=%d attested=%v",
		req.Method, destination, resp.StatusCode, len(findings), sigHex != "")

	telemetry.SubmitGlobal(telemetry.NewToolCallEvent(
		p.agentID, "egress_proxy", destination,
		telemetry.StatusSuccess,
		fmt.Sprintf("egress forwarded HTTP %d", resp.StatusCode),
	))

	return resp, nil
}

// Metrics returns a snapshot of the proxy's operational counters.
func (p *EgressProxy) Metrics() (allowed, blocked, dlpHits int64) {
	return atomic.LoadInt64(&p.requestsAllowed),
		atomic.LoadInt64(&p.requestsBlocked),
		atomic.LoadInt64(&p.dlpFindings)
}
