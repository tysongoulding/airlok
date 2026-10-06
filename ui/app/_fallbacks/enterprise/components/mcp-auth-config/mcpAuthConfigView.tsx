import React, { useState } from "react";
import { ShieldUser, Key, Lock, CheckCircle2, RefreshCw, Cpu, Layers } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Switch } from "@/components/ui/switch";
import { toast } from "sonner";

interface MCPAuthServer {
	id: string;
	serverName: string;
	transport: "SSE" | "HTTP" | "Stdio";
	authMode: "OAuth2 Token Exchange" | "Injected Bearer Header" | "Per-User Vault Secret";
	credentialState: "Injected & Isolated";
	activeUsers: number;
}

const SERVERS: MCPAuthServer[] = [
	{
		id: "mcp-github",
		serverName: "github-enterprise-mcp",
		transport: "HTTP",
		authMode: "OAuth2 Token Exchange",
		credentialState: "Injected & Isolated",
		activeUsers: 28,
	},
	{
		id: "mcp-postgres",
		serverName: "secure-db-mcp",
		transport: "SSE",
		authMode: "Injected Bearer Header",
		credentialState: "Injected & Isolated",
		activeUsers: 14,
	},
	{
		id: "mcp-slack",
		serverName: "slack-corp-mcp",
		transport: "HTTP",
		authMode: "Per-User Vault Secret",
		credentialState: "Injected & Isolated",
		activeUsers: 45,
	},
];

export default function MCPAuthConfigView() {
	const [servers, setServers] = useState<MCPAuthServer[]>(SERVERS);

	return (
		<div className="space-y-6">
			{/* Header */}
			<div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
				<div>
					<div className="flex items-center gap-2">
						<h1 className="text-2xl font-bold tracking-tight text-foreground">MCP Federated Auth & Credential Isolation</h1>
						<Badge variant="outline" className="bg-emerald-500/10 text-emerald-500 border-emerald-500/20">
							Active
						</Badge>
					</div>
					<p className="text-sm text-muted-foreground mt-0.5">
						External AI harnesses connect with a single SplitGate key while SplitGate dynamically injects isolated downstream credentials.
					</p>
				</div>
				<div className="flex items-center gap-2">
					<Button
						variant="outline"
						size="sm"
						onClick={() => toast.success("Token exchange policies re-synchronized with MCP Gateway")}
					>
						<RefreshCw className="mr-1.5 h-3.5 w-3.5" />
						Sync Credentials
					</Button>
				</div>
			</div>

			{/* Architecture Info Card */}
			<Card className="border-primary/20 bg-muted/20">
				<CardHeader className="pb-3">
					<CardTitle className="text-sm font-semibold">Dual-Role Routing & Credential Isolation Architecture</CardTitle>
					<CardDescription className="text-xs">
						Harnesses (Claude, Cursor, Codex) connect via single TLS/SSE connection to SplitGate. Downstream tool secrets and OAuth tokens never leak to the client harness.
					</CardDescription>
				</CardHeader>
			</Card>

			{/* Servers Table */}
			<Card>
				<CardHeader>
					<CardTitle className="text-base font-semibold">Federated Tool Servers</CardTitle>
					<CardDescription>
						Connected downstream MCP servers configured with dynamic credential injection and per-user token minting.
					</CardDescription>
				</CardHeader>
				<CardContent className="p-0">
					<div className="overflow-x-auto">
						<table className="w-full text-left text-sm">
							<thead className="border-b bg-muted/40 text-xs font-medium text-muted-foreground uppercase">
								<tr>
									<th className="px-4 py-3">Server Identifier</th>
									<th className="px-4 py-3">Transport</th>
									<th className="px-4 py-3">Authentication Strategy</th>
									<th className="px-4 py-3">Credential State</th>
									<th className="px-4 py-3 text-right">Active Sessions</th>
								</tr>
							</thead>
							<tbody className="divide-y">
								{servers.map((s) => (
									<tr key={s.id} className="hover:bg-muted/20 transition-colors">
										<td className="px-4 py-3.5 font-medium text-foreground">
											{s.serverName}
										</td>
										<td className="px-4 py-3.5">
											<Badge variant="outline" className="font-mono text-xs">
												{s.transport}
											</Badge>
										</td>
										<td className="px-4 py-3.5 text-xs text-muted-foreground">
											{s.authMode}
										</td>
										<td className="px-4 py-3.5">
											<Badge className="bg-emerald-500/10 text-emerald-500 border-emerald-500/20">
												{s.credentialState}
											</Badge>
										</td>
										<td className="px-4 py-3.5 text-right font-mono text-xs">
											{s.activeUsers} users
										</td>
									</tr>
								))}
							</tbody>
						</table>
					</div>
				</CardContent>
			</Card>
		</div>
	);
}