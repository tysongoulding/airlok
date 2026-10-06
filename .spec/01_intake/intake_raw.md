# Phase 1: Intake Specification — Airlok on Bifrost Execution Boundary

**Persona**: Product Architect  
**Status**: Complete  
**Date**: 2026-10-05  
**Base Platform**: `github.com/maximhq/bifrost`  
**Feature/Module**: Airlok Dual-Gateway & Governance Platform  

---

## 1. Problem Statement & User Intent

### Core Objective
Fork and build upon **Bifrost** (`maximhq/bifrost`) — a high-performance (~11µs overhead) AI & MCP gateway written in Go with 20+ LLM providers and an agentic tool-calling engine — to create **Airlok**: a comprehensive, secure, local-to-cloud execution boundary for AI coding agent harnesses (**Cursor, Claude Code/Desktop, Google Antigravity, Pi**).

Airlok realizes the target architecture:
1. **Harness Interface**: Drop-in SDK compatibility and environment presets for Cursor, Claude Code, Antigravity, and Pi.
2. **LLM Gateway Plane**: High-throughput multi-model routing across Google Gemini, Anthropic Claude, xAI Grok, and OpenAI ChatGPT.
3. **Connector Gateway Plane**: Extensible SaaS and tool execution boundary leveraging Bifrost's native Model Context Protocol (MCP) engine (Google Workspace, Slack, Office365, and 3000+ connectors).
4. **Bidirectional Control Channel (`Ctrl`)**: Dynamic tool discovery, schema injection, and multi-turn tool execution loop between the LLM and Connector planes.
5. **Dual-Plane Access Control List (ACL)**: Unified governance matrix enforcing granular allow/audit/deny policies across both LLMs (Gemini/Grok allowed, Claude audited, ChatGPT blocked) and Connectors (Workspace/Slack allowed, 3000+ managed, Office365 blocked).
6. **Storage & Git Sync Engine**: Persistent storage bridging harness session history, checkpoints, and configurations to Git repositories.
7. **Local-to-Cloud Evolution**: Zero-dependency local developer execution (single binary + embedded Web UI + local SQLite/file store) transitioning seamlessly to distributed cloud deployment (Postgres, clustering, Helm, Terraform).

---

## 2. Bifrost Baseline vs. Airlok Target Gap Analysis

| Capability / Plane | Bifrost Out-of-the-Box (`maximhq/bifrost`) | Airlok Target Architecture | Gap Classification |
|---|---|---|---|
| **LLM Gateway** | ✅ 20+ LLM providers (Gemini, Claude, OpenAI, Grok via OpenAI, Bedrock) | ✅ Unified model routing with fallbacks and streaming | **Fully Covered by Bifrost** |
| **Connector Gateway** | ✅ Native MCP Gateway (Stdio/SSE clients, tool discovery, agent loop) | ✅ Google Workspace, Slack, Office365, 3000+ connectors | **Pre-packaged Presets Needed** |
| **Bidirectional `Ctrl` Loop** | ✅ Built-in agentic tool-calling loop (`core/mcp/agent.go`) | ✅ Schema injection & multi-turn tool execution | **Fully Covered by Bifrost** |
| **Harness OAuth & Identity** | ⚠️ Admin-configured API keys & static MCP tokens | ✅ User-delegated OAuth 2.0 PKCE for harnesses | **Extension Required**: Add user OAuth flow for developer harnesses to authorize SaaS connectors. |
| **Dual-Plane ACL Matrix** | ⚠️ Virtual keys, budgets, rate limits, RBAC | ✅ Visual policy parity: `LLM` rules + `CON` rules + cross-plane leak checks | **Extension Required**: Add dual-plane ACL policy engine in `plugins/governance/`. |
| **Storage & Git Sync** | ⚠️ File / Postgres configstore & logstore | ✅ Automated GitOps sync for sessions, checkpoints, and configs | **Extension Required**: Add Git sync worker to configstore/session engine. |
| **Local to Cloud** | ✅ Local binary + Web UI / Cloud Postgres + K8s | ✅ Local-first daemon migrating to cloud cluster | **Fully Covered by Bifrost** |

---

## 3. Confirmed Architectural Decisions
1. **Connector Strategy**: Hybrid Model Context Protocol (MCP) runner for local tools + OAuth SaaS adapters (Google Workspace, Slack, Office365).
2. **Local Form Factor**: Run as single all-in-one Go binary (`bifrost-http` / `airlok`) with embedded UI and local file/SQLite store.
3. **Storage & Git Scope**: Unified GitOps & Audit — Store ACL policies, connector configs, and session checkpoints in Git.
