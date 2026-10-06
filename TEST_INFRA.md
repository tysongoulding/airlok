# Airlok Enterprise Test Infrastructure & 4-Tier E2E Architecture

## Overview
The Airlok Enterprise test suite (`tests/e2e/enterprise/`) provides a comprehensive, deterministic, and self-contained end-to-end verification harness for the Airlok Enterprise extension suite (R1–R8) built on Bifrost AI Gateway.

All tests execute with **zero external cloud dependencies** by leveraging deterministic mock infrastructure simulating AWS, Azure, Google Cloud, HashiCorp Vault, OIDC/SAML Identity Providers, SCIM 2.0 endpoints, Redis/gossip distributed state, and cluster memberlists.

---

## 4-Tier Test Suite Architecture

```
tests/e2e/enterprise/
├── mock/                                 # Deterministic In-Memory Enterprise Infrastructure
│   ├── guardrails.go                     # R1: RE2 Regex, PII Templates, Secrets, External Hooks, CEL, Streaming
│   ├── cluster.go                        # R2: P2P Memberlist Gossip, Node Discovery, Election, Rate Limit Sync
│   ├── loadbalancer.go                   # R3: EWMA Latency Scoring, 4 Health States, Held Keys, Circuit Breakers
│   ├── sso_vault.go                      # R4 & R5: RSA JWKS, JIT Provisioning, SCIM, Vault KV v2, TTL Cache, Flush
│   ├── mcp.go                            # R6: RFC 8693 Token Exchange, Virtual MCPs, Dual-Plane ACL, Cross-Plane
│   ├── audit_rbac.go                     # R7 & R8: HMAC-SHA256 Ledger, IP Omission, S3 Offloader, RBAC, SLA & Health
│   └── gateway_server.go                 # Integrated Test Gateway Server (Fasthttp/HTTP test server)
├── guardrails_test.go                    # R1 Tests: Tiers 1 & 2
├── cluster_test.go                       # R2 Tests: Tiers 1 & 2
├── loadbalancer_test.go                  # R3 Tests: Tiers 1 & 2
├── sso_vault_test.go                     # R4 & R5 Tests: Tiers 1 & 2
├── mcp_test.go                           # R6 Tests: Tiers 1 & 2
├── audit_rbac_test.go                    # R7 & R8 Tests: Tiers 1 & 2
├── harness_test.go                       # Coding Harness Presets (Cursor, Claude, Antigravity, Pi) & GitOps Checkpoints
├── combinations_test.go                  # Tier 3: Pairwise Cross-Feature Interactions
├── scenarios_test.go                     # Tier 4: Real-World Enterprise Production Scenarios
└── go.mod                                # Standalone Go module wired into go.work
```

---

## Tier Methodology

### Tier 1: Feature Coverage (>=5 test cases per feature for R1–R8)
- **R1: Content Guardrails Pipeline**:
  - In-process RE2 regex scanning (<1ms budget)
  - PII detection & blocking: SSN & credit card with HTTP 422 `guardrail_violation`
  - PII redaction: Email & Phone with `[EMAIL]`, `[PHONE]` replacement
  - Secrets detection: AWS Access Key ID, JWT tokens, RSA private keys
  - External hooks: AWS Bedrock Guardrails, Azure AI Content Safety, Google Model Armor
  - CEL expression targeting: Condition-based policy activation on model/provider metadata
  - Streaming output guardrail: Chunk buffering, safety verification, and dynamic intervention
- **R2: High-Availability Cluster Mode & Distributed State**:
  - P2P memberlist gossip join and heartbeat liveness on port 10101
  - Deterministic lexicographical leader election
  - Automated peer discovery (Kubernetes, DNS, UDP)
  - gRPC application state broadcast on port 10102
  - Distributed rate limit token bucket synchronization without drift
  - Centralized broker relay mode on port 50051
- **R3: Adaptive Load Balancing & Circuit Breakers**:
  - Multi-factor route scoring: EWMA Latency (alpha=0.2), error penalty, utilization penalty
  - 4-state lifecycle transitions: `Healthy` -> `Degraded` -> `Failed` -> `Recovering`
  - Held keys mechanism: Provider refusals (401, 402, 429) trigger backoff ladder (30s, 60s, up to cap)
  - Circuit breaker response header signals (e.g. `X-Ms-Is-Spilled-Over: true`)
  - Dynamic failover rerouting to fallback provider and model
- **R4: Enterprise SSO & Identity Provider**:
  - RS256 JWKS JWT signature verification against public keys
  - JIT (Just-In-Time) user account provisioning
  - Group-to-role translation (`attributeRoleMappings`) to `Admin`, `Developer`, `Security Auditor`, `Operator`
  - Inbound SCIM 2.0 API user provisioning (`/scim/v2/Users`)
  - Unmapped role login rejection with HTTP 403
- **R5: Secret Management & Vault Integration**:
  - Canonical (`vault.<path>`) and fragment (`vault.<path>#<field>`) reference resolution
  - HashiCorp Vault KV v2, AWS Secrets Manager, and GCP Secret Manager mock backends
  - In-memory TTL caching with background rotation worker
  - Instant fleet-wide cache eviction via `POST /api/vault/flush-cache`
- **R6: Federated MCP Authorization & Tool Governance**:
  - RFC 8693 OAuth 2.0 Token Exchange (`GetExchangedAccessToken`)
  - Multi-tenant Virtual MCP endpoints (`/mcp/<slug>`)
  - Dual-plane ACL: Allow (`google_workspace`, `slack`), Deny (`office365`), Require Approval (`catalog_3000`)
  - Cross-plane data boundary protection: Prevents sensitive connector data from leaking into prohibited LLMs
  - Per-user tool visibility filtering
- **R7: Log Exports & Audit Trail Pipeline**:
  - Tamper-evident audit logging signed with HMAC-SHA256 (`hmac_key` >= 32 bytes)
  - GDPR/employee privacy IP address omission (`omit_ip_addresses: true`)
  - Asynchronous batched log queue flusher (batch size and interval triggers)
  - S3 / GCS payload offloader for large request/response bodies with windowed JSONL archival
- **R8: Granular RBAC & Enterprise Diagnostics**:
  - RBAC authorization middleware across 17+ resources and operations
  - Granular system roles: `Admin`, `Developer`, `Security Auditor`, `Operator`
  - SLA Diagnostic endpoint (`GET /api/v1/enterprise/diagnostics/sla?window=24h`)
  - Health bundle export endpoint (`GET /api/v1/enterprise/diagnostics/health-bundle`) packaging valid gzip archive

### Tier 2: Boundary & Corner Cases (>=5 test cases per feature for R1–R8)
- Empty prompts, 200KB extreme payloads, overlapping redaction spans, invalid CEL syntax fallback, zero-chunk stream handling, case-insensitive regex flag matching.
- Cluster network partition split-brain handling, rapid concurrent token bursts, zero-peer startup, leader crash immediate re-election, rate limit refill after window expiry.
- Simultaneous failure of all primary routes with automatic fallback, zero-traffic minimum probe weight preservation (0.1), flapping error rates, held key wait ladder capping at 15 minutes, custom `Retry-After` header parsing.
- Expired JWT token rejection, tampered JWT payload signature failure, malformed token segments, SCIM duplicate user collision.
- Non-existent vault secret path error, missing field fragment error, concurrent cache access race safety under `-race`.
- Missing subject token on token exchange, expired subject token, non-existent virtual MCP slug, unauthorized cross-plane destination model, wildcard tool permissions.
- HMAC key shorter than 32 bytes rejection, empty log queue flush no-op, undefined role denial, undefined resource denial, default 24h SLA window query parameter handling.

### Tier 3: Cross-Feature Combinations (Pairwise Interactions)
1. **SSO + Guardrails + Load Balancer + Audit Trail**: OIDC authenticated user sends PII prompt; email is redacted at runtime; request is routed via adaptive key scoring; audit ledger records signed HMAC entry.
2. **Virtual MCP + Token Exchange + Vault + RBAC**: Developer user accesses `/mcp/analytics`; exchanges token for downstream DB; resolves credentials from Vault; verified against RBAC permissions.
3. **Cluster Distributed Rate Limit + Load Balancer Failover**: Multi-node cluster synchronizes token buckets while primary provider route experiences latency spike; traffic shifts to secondary provider while rate limits remain strictly synchronized across nodes.
4. **Guardrail Redaction + S3 Payload Offloader + Audit IP Omission**: PII prompt is redacted; large output body is offloaded to S3; audit trail records transaction with client IP sanitized.
5. **Circuit Breaker Spillover + Vault Dynamic Flush + Audit Security Incident**: Spillover header trips breaker to fallback model; vault cache is flushed fleet-wide; audit ledger signs the failover event.
6. **Inbound SCIM Provisioning + RBAC Boundary + Audit Verification**: New SCIM developer provisioned; attempts unauthorized Admin operation; rejected with HTTP 403; audit logs record security rejection.

### Tier 4: Real-World Enterprise Production Scenarios
1. **Enterprise Financial Assistant**: High-compliance banking analyst authenticates via SSO; prompt with SSN is blocked with HTTP 422; sanitized prompt has credit card masked; routed through healthy provider keys; financial report offloaded to S3; HMAC signed audit record.
2. **Multi-Tenant Agent Workflow**: Autonomous agent acts across `/mcp/finance` and `/mcp/ops`; performs RFC 8693 token exchange; dual-plane ACL and cross-plane data boundary blocks Slack connector data from leaking into public OpenAI model; enforces distributed rate limits.
3. **Disaster Recovery Failover**: Datacenter provider suffers latency spike and `X-Ms-Is-Spilled-Over` spillover header; circuit breaker trips; 100% traffic dynamically reroutes to Anthropic; cluster nodes broadcast health update via gRPC; SLA diagnostic endpoint captures degraded period and uptime.
4. **Regulatory Compliance Audit & Key Rotation**: Security Auditor logs in with `Security Auditor` role; downloads SLA performance metrics and gzip health bundle; executes `POST /api/vault/flush-cache` fleet-wide rotation; audits HMAC signatures across ledger entries; verifies client IP omission compliance.

---

## How to Run the Tests

```bash
# Run all Enterprise E2E tests
go test -v ./tests/e2e/enterprise/...

# Run with race condition detector
go test -race ./tests/e2e/enterprise/...

# Run specific tier or feature
go test -v -run TestGuardrails ./tests/e2e/enterprise/...
go test -v -run TestCluster ./tests/e2e/enterprise/...
go test -v -run TestLoadBalancer ./tests/e2e/enterprise/...
go test -v -run TestSSO_Tier ./tests/e2e/enterprise/...
go test -v -run TestMCP ./tests/e2e/enterprise/...
go test -v -run TestAudit ./tests/e2e/enterprise/...
go test -v -run TestCombinations ./tests/e2e/enterprise/...
go test -v -run TestScenario ./tests/e2e/enterprise/...
```
