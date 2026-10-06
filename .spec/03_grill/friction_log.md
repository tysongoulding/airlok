# Phase 3: Friction Log — Adversarial Architectural Critique (Bifrost)

**Persona**: Adversarial Reviewer  
**Status**: Open / Active  
**Date**: 2026-10-05  
**Target Reference**: `.spec/02_planning/architectural_plan.md`  

---

## 1. Executive Summary
Bifrost provides a mature, battle-tested Go core for high-throughput LLM proxying and MCP tool calling. However, integrating the Airlok execution boundary introduces several security and concurrency risks:
1. **F-01: Multi-Turn MCP Execution Latency**: When an agent executes nested tool calls in `core/mcp/agent.go`, long-running SaaS calls (Slack, Google Workspace) can cause IDE HTTP timeouts in Cursor or Claude Code.
2. **F-02: OAuth Token Exposure in Local Configuration**: Storing developer OAuth tokens in Bifrost's `config.json` exposes them to accidental git commits or file leaks.
3. **F-03: Cross-Plane Indirect Injection Leaks**: A permitted model (Gemini) reading private data from Google Workspace could be induced to exfiltrate data via a blocked model or unapproved tool.
4. **F-04: Git Lock Collisions on High-Frequency Agent Iteration**: Rapid checkpointing corrupting `.git/index.lock`.
