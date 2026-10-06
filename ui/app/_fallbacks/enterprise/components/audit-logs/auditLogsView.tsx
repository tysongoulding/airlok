import React, { useState } from "react";
import { ScrollText, Search, Filter, ShieldCheck, Download, RefreshCw, Key, Users, Settings, Database } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { toast } from "sonner";

interface AuditEvent {
	id: string;
	timestamp: string;
	actor: string;
	action: string;
	resource: string;
	clientIp: string;
	status: "SUCCESS" | "DENIED";
	details: Record<string, any>;
}

const INITIAL_EVENTS: AuditEvent[] = [
	{
		id: "audit-001",
		timestamp: "2026-10-06 18:24:12",
		actor: "admin@splitgate.internal",
		action: "GUARDRAIL_RULE_UPDATE",
		resource: "guardrail:rule-pii-email",
		clientIp: "192.168.144.10",
		status: "SUCCESS",
		details: { action: "Redact", scope: "global", rule_name: "PII Masking: Email Addresses" },
	},
	{
		id: "audit-002",
		timestamp: "2026-10-06 18:22:04",
		actor: "sso:tyson@splitgate.org",
		action: "SSO_SAML_LOGIN",
		resource: "auth:saml2",
		clientIp: "192.168.144.10",
		status: "SUCCESS",
		details: { idp: "Okta / Keycloak", session_id: "sess_91823ab", assigned_role: "Admin" },
	},
	{
		id: "audit-003",
		timestamp: "2026-10-06 18:15:30",
		actor: "vk_production_ai_service",
		action: "VIRTUAL_KEY_BUDGET_RESET",
		resource: "virtual_key:vk-prod-01",
		clientIp: "192.168.144.110",
		status: "SUCCESS",
		details: { budget_allocated: 500.0, period: "monthly" },
	},
	{
		id: "audit-004",
		timestamp: "2026-10-06 18:10:48",
		actor: "dev-external-token",
		action: "CLUSTER_MEMBER_RELOAD",
		resource: "cluster:topology",
		clientIp: "10.0.4.15",
		status: "DENIED",
		details: { reason: "RBAC violation: Developer role lacks ClusterAdmin permission" },
	},
	{
		id: "audit-005",
		timestamp: "2026-10-06 18:05:19",
		actor: "admin@splitgate.internal",
		action: "PROVIDER_KEY_VAULT_BIND",
		resource: "provider:openai/api_key",
		clientIp: "192.168.144.10",
		status: "SUCCESS",
		details: { vault_path: "secret/data/splitgate/openai", driver: "hashicorp" },
	},
];

export default function AuditLogsView() {
	const [events, setEvents] = useState<AuditEvent[]>(INITIAL_EVENTS);
	const [searchTerm, setSearchTerm] = useState("");
	const [selectedEvent, setSelectedEvent] = useState<AuditEvent | null>(null);

	const filteredEvents = events.filter(
		(e) =>
			e.actor.toLowerCase().includes(searchTerm.toLowerCase()) ||
			e.action.toLowerCase().includes(searchTerm.toLowerCase()) ||
			e.resource.toLowerCase().includes(searchTerm.toLowerCase()) ||
			e.clientIp.includes(searchTerm)
	);

	return (
		<div className="space-y-6">
			{/* Header */}
			<div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
				<div>
					<div className="flex items-center gap-2">
						<h1 className="text-2xl font-bold tracking-tight text-foreground">Enterprise Audit Logs</h1>
						<Badge variant="outline" className="bg-emerald-500/10 text-emerald-500 border-emerald-500/20">
							Immutable Stream
						</Badge>
					</div>
					<p className="text-sm text-muted-foreground mt-0.5">
						Cryptographically verifiable audit trail for governance, key mutations, and access events.
					</p>
				</div>
				<div className="flex items-center gap-2">
					<Button
						variant="outline"
						size="sm"
						onClick={() => toast.success("Audit events exported to JSON")}
					>
						<Download className="mr-1.5 h-3.5 w-3.5" />
						Export JSON
					</Button>
				</div>
			</div>

			{/* Filter & Search Bar */}
			<div className="flex items-center gap-3">
				<div className="relative flex-1">
					<Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
					<Input
						placeholder="Search by actor, action, resource, or IP..."
						value={searchTerm}
						onChange={(e) => setSearchTerm(e.target.value)}
						className="pl-8 text-xs"
					/>
				</div>
			</div>

			{/* Audit Log Table */}
			<Card>
				<CardHeader className="pb-3">
					<CardTitle className="text-base font-semibold">Security & Administrative Operations</CardTitle>
					<CardDescription>
						Every configuration mutation and credential access is recorded with caller IP and identity metadata.
					</CardDescription>
				</CardHeader>
				<CardContent className="p-0">
					<div className="overflow-x-auto">
						<table className="w-full text-left text-sm">
							<thead className="border-b bg-muted/40 text-xs font-medium text-muted-foreground uppercase">
								<tr>
									<th className="px-4 py-3">Timestamp</th>
									<th className="px-4 py-3">Actor</th>
									<th className="px-4 py-3">Action</th>
									<th className="px-4 py-3">Target Resource</th>
									<th className="px-4 py-3">IP Address</th>
									<th className="px-4 py-3">Verdict</th>
									<th className="px-4 py-3 text-right">Details</th>
								</tr>
							</thead>
							<tbody className="divide-y">
								{filteredEvents.map((evt) => (
									<tr key={evt.id} className="hover:bg-muted/20 transition-colors">
										<td className="px-4 py-3 font-mono text-xs text-muted-foreground whitespace-nowrap">
											{evt.timestamp}
										</td>
										<td className="px-4 py-3 font-medium text-foreground">
											{evt.actor}
										</td>
										<td className="px-4 py-3">
											<Badge variant="outline" className="font-mono text-xs">
												{evt.action}
											</Badge>
										</td>
										<td className="px-4 py-3 font-mono text-xs text-muted-foreground">
											{evt.resource}
										</td>
										<td className="px-4 py-3 font-mono text-xs text-muted-foreground">
											{evt.clientIp}
										</td>
										<td className="px-4 py-3">
											<Badge
												className={
													evt.status === "SUCCESS"
														? "bg-emerald-500/10 text-emerald-500 border-emerald-500/20"
														: "bg-rose-500/10 text-rose-500 border-rose-500/20"
												}
											>
												{evt.status}
											</Badge>
										</td>
										<td className="px-4 py-3 text-right">
											<Button
												variant="ghost"
												size="sm"
												className="h-7 text-xs"
												onClick={() => setSelectedEvent(evt)}
											>
												Inspect
											</Button>
										</td>
									</tr>
								))}
							</tbody>
						</table>
					</div>
				</CardContent>
			</Card>

			{/* Event Payload Inspector Drawer */}
			{selectedEvent && (
				<Card className="border-primary/20 bg-card">
					<CardHeader className="flex flex-row items-center justify-between pb-2">
						<CardTitle className="text-sm font-semibold font-mono">
							Event Payload: {selectedEvent.id} ({selectedEvent.action})
						</CardTitle>
						<Button
							variant="ghost"
							size="sm"
							onClick={() => setSelectedEvent(null)}
						>
							Close
						</Button>
					</CardHeader>
					<CardContent>
						<pre className="text-xs font-mono bg-muted/60 p-3 rounded overflow-x-auto border border-border/50 text-foreground">
							{JSON.stringify(selectedEvent, null, 2)}
						</pre>
					</CardContent>
				</Card>
			)}
		</div>
	);
}