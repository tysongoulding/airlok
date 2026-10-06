# Phase 3: Mitigation Plan & Hardening Matrix (Bifrost)

**Persona**: Adversarial Reviewer  
**Status**: Resolved / Hardened  
**Date**: 2026-10-05  
**Friction Reference**: `.spec/03_grill/friction_log.md`  

---

## 1. Mitigation Mapping

| Friction ID | Severity | Root Cause | Engineering Mitigation | Target Layer |
|---|---|---|---|---|
| **F-01** | High | Multi-turn tool execution latency causing IDE connection timeouts | Enforce per-tool execution timeouts (default 15s) and leverage Bifrost's `HTTPTransportStreamChunkHook` to stream keep-alive pings during tool execution | `core/mcp/` & `transports/bifrost-http/` |
| **F-02** | Critical | OAuth tokens stored in `config.json` exposed to Git | Store user-delegated tokens in isolated AES-256 encrypted keystore at `~/.airlok/vault.json` (outside git tree), and enforce pre-commit secret regex scanning | `framework/gitstore/` & `transports/` |
| **F-03** | Critical | Cross-plane data exfiltration via indirect prompt injection | Fail-closed policy evaluation in `PreLLMHook` and `PreMCPHook`: reject blocked models (OpenAI ChatGPT) and blocked tools (Office365) before network dispatch | `plugins/governance/acl.go` |
| **F-04** | Medium | Git index lock collisions from frequent commits | Debounce git commits with 5-second minimum cooldown and asynchronous queueing | `framework/gitstore/git_syncer.go` |
