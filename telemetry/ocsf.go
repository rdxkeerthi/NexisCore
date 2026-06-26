// Package telemetry implements OCSF-compliant structured event logging and
// asynchronous forwarding to SIEM platforms (e.g., Splunk HEC).
//
// OCSF class UIDs used:
//   - 6002 — Application Activity  (tool calls, sandbox launches)
//   - 2001 — Security Finding      (validation failures, tampering, DLP hits)
package telemetry

import (
	"encoding/json"
	"fmt"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// OCSF Class UIDs
// ─────────────────────────────────────────────────────────────────────────────

const (
	// ClassApplicationActivity maps to OCSF class_uid 6002
	ClassApplicationActivity = 6002
	// ClassSecurityFinding maps to OCSF class_uid 2001
	ClassSecurityFinding = 2001
)

// ─────────────────────────────────────────────────────────────────────────────
// OCSF Activity IDs (per class)
// ─────────────────────────────────────────────────────────────────────────────

const (
	ActivityUnknown   = 0
	ActivityCreate    = 1
	ActivityRead      = 2
	ActivityUpdate    = 3
	ActivityDelete    = 4
	ActivityExecute   = 5
	ActivityAllow     = 6
	ActivityDeny      = 7
	ActivityAudit     = 8
	ActivityEncode    = 9
	ActivityDecode    = 10
	ActivityTerminate = 99
)

// ─────────────────────────────────────────────────────────────────────────────
// OCSF Severity IDs
// ─────────────────────────────────────────────────────────────────────────────

const (
	SeverityUnknown       = 0
	SeverityInformational = 1
	SeverityLow           = 2
	SeverityMedium        = 3
	SeverityHigh          = 4
	SeverityCritical      = 5
	SeverityFatal         = 6
)

// ─────────────────────────────────────────────────────────────────────────────
// OCSF Status Codes
// ─────────────────────────────────────────────────────────────────────────────

const (
	StatusUnknown = 0
	StatusSuccess = 1
	StatusFailure = 2
)

// ─────────────────────────────────────────────────────────────────────────────
// Core OCSF Structs
// ─────────────────────────────────────────────────────────────────────────────

// OCSFActor describes the initiating entity of an event.
type OCSFActor struct {
	// User is the human or service account identity (e.g. agent SPIFFE ID or username).
	User string `json:"user,omitempty"`
	// Process holds the process name that initiated the action.
	Process string `json:"process,omitempty"`
	// SessionUID is an optional per-request correlation token.
	SessionUID string `json:"session_uid,omitempty"`
}

// OCSFResource describes the target resource of an event.
type OCSFResource struct {
	// Name is the logical name of the resource (tool name, endpoint, file path, etc.).
	Name string `json:"name,omitempty"`
	// Type is a free-form resource type label.
	Type string `json:"type,omitempty"`
	// UID is an optional unique identifier for the resource.
	UID string `json:"uid,omitempty"`
}

// OCSFMetadata contains schema and product identification information.
type OCSFMetadata struct {
	// Version is the OCSF schema version in use.
	Version string `json:"version"`
	// Product is the originating product name.
	Product string `json:"product"`
	// Vendor is the product vendor/author name.
	Vendor string `json:"vendor"`
	// EventCode is a product-specific event code for correlation.
	EventCode string `json:"event_code,omitempty"`
}

// OCSFEvent is a fully standards-compliant OCSF event payload. It targets both
// the Application Activity (6002) and Security Finding (2001) class schemas.
type OCSFEvent struct {
	// ClassUID identifies the OCSF class (6002 or 2001).
	ClassUID int `json:"class_uid"`
	// ClassName is the human-readable OCSF class name.
	ClassName string `json:"class_name"`
	// ActivityID identifies the specific activity within the class.
	ActivityID int `json:"activity_id"`
	// ActivityName is the human-readable activity label.
	ActivityName string `json:"activity_name"`
	// Time is the Unix epoch millisecond timestamp of the event.
	Time int64 `json:"time"`
	// SeverityID is the numeric OCSF severity level (0–6).
	SeverityID int `json:"severity_id"`
	// Severity is the human-readable severity string.
	Severity string `json:"severity"`
	// StatusID is the numeric outcome status (0=Unknown, 1=Success, 2=Failure).
	StatusID int `json:"status_id"`
	// Status is the human-readable outcome status string.
	Status string `json:"status"`
	// StatusDetail provides additional context about the status outcome.
	StatusDetail string `json:"status_detail,omitempty"`
	// AgentID is the NexisCore agent UUID that generated this event.
	AgentID string `json:"agent_id"`
	// Actor describes the initiating entity.
	Actor OCSFActor `json:"actor"`
	// Resource is the target of the action.
	Resource OCSFResource `json:"resource"`
	// Action is a concise verb describing what occurred (e.g. "tool_call", "attestation").
	Action string `json:"action"`
	// SignatureVerificationStatus is "verified", "failed", or "n/a".
	SignatureVerificationStatus string `json:"signature_verification_status"`
	// Metadata contains OCSF schema and product identification.
	Metadata OCSFMetadata `json:"metadata"`
	// RawData is an optional free-form JSON object carrying supplemental context.
	RawData json.RawMessage `json:"raw_data,omitempty"`
	// FindingType is only populated for Security Finding (2001) events.
	FindingType string `json:"finding_type,omitempty"`
	// FindingUID is a deduplicated finding identifier for SIEM correlation.
	FindingUID string `json:"finding_uid,omitempty"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Package-level helpers
// ─────────────────────────────────────────────────────────────────────────────

var nexiscoreMetadata = OCSFMetadata{
	Version: "1.1.0",
	Product: "NexisCore",
	Vendor:  "NexisCore Security",
}

func nowMS() int64 { return time.Now().UnixMilli() }

func severityName(id int) string {
	switch id {
	case SeverityInformational:
		return "Informational"
	case SeverityLow:
		return "Low"
	case SeverityMedium:
		return "Medium"
	case SeverityHigh:
		return "High"
	case SeverityCritical:
		return "Critical"
	case SeverityFatal:
		return "Fatal"
	default:
		return "Unknown"
	}
}

func statusName(id int) string {
	switch id {
	case StatusSuccess:
		return "Success"
	case StatusFailure:
		return "Failure"
	default:
		return "Unknown"
	}
}

func activityName(id int) string {
	switch id {
	case ActivityCreate:
		return "Create"
	case ActivityRead:
		return "Read"
	case ActivityUpdate:
		return "Update"
	case ActivityDelete:
		return "Delete"
	case ActivityExecute:
		return "Execute"
	case ActivityAllow:
		return "Allow"
	case ActivityDeny:
		return "Deny"
	case ActivityAudit:
		return "Audit"
	case ActivityEncode:
		return "Encode"
	case ActivityDecode:
		return "Decode"
	case ActivityTerminate:
		return "Terminate"
	default:
		return "Unknown"
	}
}

// Marshal serialises the event to a standards-compliant JSON byte slice.
func (e *OCSFEvent) Marshal() ([]byte, error) {
	return json.Marshal(e)
}

// ─────────────────────────────────────────────────────────────────────────────
// Event Constructors
// ─────────────────────────────────────────────────────────────────────────────

// NewToolCallEvent constructs an OCSF Application Activity event for an MCP
// tool invocation. Pass statusID = StatusSuccess or StatusFailure.
func NewToolCallEvent(agentID, actorUser, toolName string, statusID int, detail string) OCSFEvent {
	return OCSFEvent{
		ClassUID:     ClassApplicationActivity,
		ClassName:    "Application Activity",
		ActivityID:   ActivityExecute,
		ActivityName: activityName(ActivityExecute),
		Time:         nowMS(),
		SeverityID:   SeverityInformational,
		Severity:     severityName(SeverityInformational),
		StatusID:     statusID,
		Status:       statusName(statusID),
		StatusDetail: detail,
		AgentID:      agentID,
		Actor:        OCSFActor{User: actorUser, Process: "nexiscore"},
		Resource:     OCSFResource{Name: toolName, Type: "mcp_tool"},
		Action:       "tool_call",
		SignatureVerificationStatus: "n/a",
		Metadata:     nexiscoreMetadata,
	}
}

// NewValidationFailEvent constructs an OCSF Security Finding event when
// signature or nonce validation fails.
func NewValidationFailEvent(agentID, actorUser, reason string, rawPayload []byte) OCSFEvent {
	var raw json.RawMessage
	if len(rawPayload) > 0 {
		raw = json.RawMessage(fmt.Sprintf(`{"error":%q}`, reason))
	}
	return OCSFEvent{
		ClassUID:     ClassSecurityFinding,
		ClassName:    "Security Finding",
		ActivityID:   ActivityDeny,
		ActivityName: activityName(ActivityDeny),
		Time:         nowMS(),
		SeverityID:   SeverityHigh,
		Severity:     severityName(SeverityHigh),
		StatusID:     StatusFailure,
		Status:       statusName(StatusFailure),
		StatusDetail: reason,
		AgentID:      agentID,
		Actor:        OCSFActor{User: actorUser, Process: "nexiscore"},
		Resource:     OCSFResource{Name: "manifest", Type: "cryptographic_proof"},
		Action:       "validation_fail",
		SignatureVerificationStatus: "failed",
		Metadata:                    nexiscoreMetadata,
		FindingType:                 "Signature Validation Failure",
		FindingUID:                  fmt.Sprintf("NEXIS-SIGFAIL-%d", nowMS()),
		RawData:                     raw,
	}
}

// NewAttestationEvent constructs an OCSF Application Activity event for a
// successful cryptographic attestation.
func NewAttestationEvent(agentID, actorUser, toolName string) OCSFEvent {
	return OCSFEvent{
		ClassUID:     ClassApplicationActivity,
		ClassName:    "Application Activity",
		ActivityID:   ActivityAudit,
		ActivityName: activityName(ActivityAudit),
		Time:         nowMS(),
		SeverityID:   SeverityInformational,
		Severity:     severityName(SeverityInformational),
		StatusID:     StatusSuccess,
		Status:       statusName(StatusSuccess),
		StatusDetail: "Provenance attestation passed",
		AgentID:      agentID,
		Actor:        OCSFActor{User: actorUser, Process: "nexiscore"},
		Resource:     OCSFResource{Name: toolName, Type: "mcp_tool"},
		Action:       "attestation",
		SignatureVerificationStatus: "verified",
		Metadata:                    nexiscoreMetadata,
	}
}

// NewKillSwitchEvent constructs an OCSF Security Finding (Critical) event
// emitted immediately before the kill-switch terminates the process.
func NewKillSwitchEvent(agentID, reason string, extraContext map[string]string) OCSFEvent {
	rawMap := make(map[string]interface{})
	rawMap["kill_reason"] = reason
	for k, v := range extraContext {
		rawMap[k] = v
	}
	rawBytes, _ := json.Marshal(rawMap)

	return OCSFEvent{
		ClassUID:     ClassSecurityFinding,
		ClassName:    "Security Finding",
		ActivityID:   ActivityTerminate,
		ActivityName: activityName(ActivityTerminate),
		Time:         nowMS(),
		SeverityID:   SeverityCritical,
		Severity:     severityName(SeverityCritical),
		StatusID:     StatusFailure,
		Status:       statusName(StatusFailure),
		StatusDetail: "Kill-switch protocol triggered: " + reason,
		AgentID:      agentID,
		Actor:        OCSFActor{User: "system", Process: "nexiscore"},
		Resource:     OCSFResource{Name: "nexiscore_process", Type: "process"},
		Action:       "kill_switch",
		SignatureVerificationStatus: "n/a",
		Metadata:                    nexiscoreMetadata,
		FindingType:                 "Runtime Tampering Detected",
		FindingUID:                  fmt.Sprintf("NEXIS-KILLSWITCH-%d", nowMS()),
		RawData:                     json.RawMessage(rawBytes),
	}
}

// NewAgentRouteEvent constructs an OCSF Application Activity event for an
// inter-agent routing decision (allow or deny).
func NewAgentRouteEvent(fromAgentID, toAgentID string, permitted bool, reason string) OCSFEvent {
	actID := ActivityAllow
	statusID := StatusSuccess
	sevID := SeverityInformational
	if !permitted {
		actID = ActivityDeny
		statusID = StatusFailure
		sevID = SeverityMedium
	}
	return OCSFEvent{
		ClassUID:     ClassApplicationActivity,
		ClassName:    "Application Activity",
		ActivityID:   actID,
		ActivityName: activityName(actID),
		Time:         nowMS(),
		SeverityID:   sevID,
		Severity:     severityName(sevID),
		StatusID:     statusID,
		Status:       statusName(statusID),
		StatusDetail: reason,
		AgentID:      fromAgentID,
		Actor:        OCSFActor{User: fromAgentID, Process: "agent_router"},
		Resource:     OCSFResource{Name: toAgentID, Type: "agent"},
		Action:       "inter_agent_route",
		SignatureVerificationStatus: "n/a",
		Metadata:                    nexiscoreMetadata,
	}
}

// NewDLPFindingEvent constructs an OCSF Security Finding event when DLP scrubs
// sensitive data from an egress payload.
func NewDLPFindingEvent(agentID, targetDomain string, findingCount int, patterns []string) OCSFEvent {
	rawBytes, _ := json.Marshal(map[string]interface{}{
		"target_domain": targetDomain,
		"finding_count": findingCount,
		"patterns_hit":  patterns,
	})
	return OCSFEvent{
		ClassUID:     ClassSecurityFinding,
		ClassName:    "Security Finding",
		ActivityID:   ActivityEncode,
		ActivityName: activityName(ActivityEncode),
		Time:         nowMS(),
		SeverityID:   SeverityHigh,
		Severity:     severityName(SeverityHigh),
		StatusID:     StatusSuccess, // Success means DLP caught and redacted it
		Status:       statusName(StatusSuccess),
		StatusDetail: fmt.Sprintf("DLP pipeline redacted %d sensitive finding(s) before egress", findingCount),
		AgentID:      agentID,
		Actor:        OCSFActor{User: "egress_proxy", Process: "nexiscore"},
		Resource:     OCSFResource{Name: targetDomain, Type: "egress_endpoint"},
		Action:       "dlp_redact",
		SignatureVerificationStatus: "n/a",
		Metadata:                    nexiscoreMetadata,
		FindingType:                 "Data Loss Prevention",
		FindingUID:                  fmt.Sprintf("NEXIS-DLP-%d", nowMS()),
		RawData:                     json.RawMessage(rawBytes),
	}
}

// NewEgressBlockEvent constructs an OCSF Security Finding for an egress
// attempt to an un-allowlisted destination.
func NewEgressBlockEvent(agentID, destination, reason string) OCSFEvent {
	rawBytes, _ := json.Marshal(map[string]string{
		"destination": destination,
		"reason":      reason,
	})
	return OCSFEvent{
		ClassUID:     ClassSecurityFinding,
		ClassName:    "Security Finding",
		ActivityID:   ActivityDeny,
		ActivityName: activityName(ActivityDeny),
		Time:         nowMS(),
		SeverityID:   SeverityHigh,
		Severity:     severityName(SeverityHigh),
		StatusID:     StatusFailure,
		Status:       statusName(StatusFailure),
		StatusDetail: "Egress blocked to unauthorized destination: " + destination,
		AgentID:      agentID,
		Actor:        OCSFActor{User: "egress_proxy", Process: "nexiscore"},
		Resource:     OCSFResource{Name: destination, Type: "egress_endpoint"},
		Action:       "egress_block",
		SignatureVerificationStatus: "n/a",
		Metadata:                    nexiscoreMetadata,
		FindingType:                 "Unauthorized Egress Attempt",
		FindingUID:                  fmt.Sprintf("NEXIS-EGRESS-%d", nowMS()),
		RawData:                     json.RawMessage(rawBytes),
	}
}

// NewMemoryTamperEvent constructs an OCSF Security Finding (Critical) when
// the memory integrity monitor detects binary modification.
func NewMemoryTamperEvent(agentID, detail string) OCSFEvent {
	rawBytes, _ := json.Marshal(map[string]string{"detail": detail})
	return OCSFEvent{
		ClassUID:     ClassSecurityFinding,
		ClassName:    "Security Finding",
		ActivityID:   ActivityTerminate,
		ActivityName: activityName(ActivityTerminate),
		Time:         nowMS(),
		SeverityID:   SeverityCritical,
		Severity:     severityName(SeverityCritical),
		StatusID:     StatusFailure,
		Status:       statusName(StatusFailure),
		StatusDetail: "Binary .text segment hash mismatch: " + detail,
		AgentID:      agentID,
		Actor:        OCSFActor{User: "system", Process: "memcheck"},
		Resource:     OCSFResource{Name: "/proc/self/exe", Type: "process_binary"},
		Action:       "memory_integrity_fail",
		SignatureVerificationStatus: "n/a",
		Metadata:                    nexiscoreMetadata,
		FindingType:                 "Memory Tampering",
		FindingUID:                  fmt.Sprintf("NEXIS-MEMTAMPER-%d", nowMS()),
		RawData:                     json.RawMessage(rawBytes),
	}
}

// NewSandboxLaunchEvent records a sandboxed execution event (start or end).
func NewSandboxLaunchEvent(agentID, toolName string, pid int, statusID int, detail string) OCSFEvent {
	rawBytes, _ := json.Marshal(map[string]interface{}{"sandbox_pid": pid})
	return OCSFEvent{
		ClassUID:     ClassApplicationActivity,
		ClassName:    "Application Activity",
		ActivityID:   ActivityExecute,
		ActivityName: activityName(ActivityExecute),
		Time:         nowMS(),
		SeverityID:   SeverityInformational,
		Severity:     severityName(SeverityInformational),
		StatusID:     statusID,
		Status:       statusName(statusID),
		StatusDetail: detail,
		AgentID:      agentID,
		Actor:        OCSFActor{User: "sandbox_manager", Process: "nexiscore"},
		Resource:     OCSFResource{Name: toolName, Type: "sandbox_container", UID: fmt.Sprintf("pid:%d", pid)},
		Action:       "sandbox_launch",
		SignatureVerificationStatus: "n/a",
		Metadata:                    nexiscoreMetadata,
		RawData:                     json.RawMessage(rawBytes),
	}
}
