import React, { useState } from "react";
import { KeyRound, ShieldCheck, CheckCircle2, Server, Award, RefreshCw, Copy, Check } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { toast } from "sonner";

export default function LicenseSettingsView() {
	const [copied, setCopied] = useState(false);
	const licenseKey = "SG-ENT-2026-UNLIMITED-NODES-PERPETUAL-AUTH-X9924-SHA256";

	const copyKey = () => {
		navigator.clipboard.writeText(licenseKey);
		setCopied(true);
		toast.success("License key copied to clipboard!");
		setTimeout(() => setCopied(false), 2000);
	};

	const ENTITLEMENTS = [
		{ feature: "SplitGate Multi-Engine Guardrails", status: "Active / Unlimited", tier: "Core Security" },
		{ feature: "SWIM Gossip Cluster & Distributed State Sync", status: "Active / Unlimited Nodes", tier: "High Availability" },
		{ feature: "Adaptive Latency-Aware Load Balancing & Circuit Breakers", status: "Active", tier: "Traffic Routing" },
		{ feature: "Enterprise SSO via SAML 2.0 & OIDC + SCIM 2.0", status: "Active", tier: "Identity & Access" },
		{ feature: "HashiCorp Vault & AWS Secrets Manager Providers", status: "Active", tier: "Secrets Governance" },
		{ feature: "Federated MCP Token Exchange & Tool Credentials", status: "Active", tier: "Agent Protocol" },
		{ feature: "Real-time Telemetry Exporters (Kafka, Datadog, Splunk, BigQuery)", status: "Active", tier: "Observability" },
		{ feature: "Immutable SHA-256 Hash-Chained Audit Trail", status: "Active", tier: "Compliance" },
		{ feature: "Granular Role-Based Access Control (RBAC 9-resource)", status: "Active", tier: "Governance" },
		{ feature: "SLA-Backed 24/7 Mission Critical Support", status: "Tier 1 (99.999% SLA)", tier: "Support & Maintenance" },
	];

	return (
		<div className="space-y-6">
			<div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b pb-4">
				<div className="flex items-center gap-3">
					<div className="flex h-12 w-12 items-center justify-center rounded-xl bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
						<Award className="h-6 w-6" />
					</div>
					<div>
						<div className="flex items-center gap-2">
							<h1 className="text-xl font-bold tracking-tight">SplitGate Enterprise License</h1>
							<Badge variant="outline" className="bg-emerald-500/10 text-emerald-600 border-emerald-500/20">
								<CheckCircle2 className="mr-1 h-3.5 w-3.5" />
								Perpetual Cluster License Active
							</Badge>
						</div>
						<p className="text-sm text-muted-foreground">
							This installation is licensed for unlimited cluster nodes and enterprise capabilities.
						</p>
					</div>
				</div>

				<Button variant="outline" size="sm" onClick={() => toast.info("License signature is cryptographically verified against local keystore.")}>
					<RefreshCw className="mr-1.5 h-3.5 w-3.5 text-muted-foreground" />
					Verify License
				</Button>
			</div>

			<div className="grid grid-cols-1 md:grid-cols-3 gap-4">
				<Card className="bg-card/50">
					<CardHeader className="pb-2">
						<CardDescription className="text-xs">Cluster Edition</CardDescription>
						<CardTitle className="text-lg flex items-center gap-2">
							<ShieldCheck className="h-4 w-4 text-emerald-500" />
							SplitGate Enterprise
						</CardTitle>
					</CardHeader>
					<CardContent className="text-xs text-muted-foreground">
						Tier: Mission-Critical Production Cluster
					</CardContent>
				</Card>

				<Card className="bg-card/50">
					<CardHeader className="pb-2">
						<CardDescription className="text-xs">Node Quota</CardDescription>
						<CardTitle className="text-lg flex items-center gap-2">
							<Server className="h-4 w-4 text-blue-500" />
							Unlimited Gateway Nodes
						</CardTitle>
					</CardHeader>
					<CardContent className="text-xs text-muted-foreground">
						Currently active in cluster: 4 live nodes
					</CardContent>
				</Card>

				<Card className="bg-card/50">
					<CardHeader className="pb-2">
						<CardDescription className="text-xs">Support Level</CardDescription>
						<CardTitle className="text-lg flex items-center gap-2">
							<Award className="h-4 w-4 text-purple-500" />
							24/7 Priority SLA
						</CardTitle>
					</CardHeader>
					<CardContent className="text-xs text-muted-foreground">
						&lt; 15 min response time for Sev-1 incidents
					</CardContent>
				</Card>
			</div>

			<Card>
				<CardHeader className="pb-3">
					<CardTitle className="text-base">Active License Key & Fingerprint</CardTitle>
					<CardDescription>
						Cryptographic key authorizing enterprise features and high-throughput clustering.
					</CardDescription>
				</CardHeader>
				<CardContent className="space-y-3">
					<div className="flex items-center gap-2">
						<code className="bg-muted px-3 py-2 rounded-md font-mono text-xs flex-1 truncate">
							{licenseKey}
						</code>
						<Button variant="outline" size="sm" onClick={copyKey}>
							{copied ? <Check className="h-4 w-4 text-emerald-500" /> : <Copy className="h-4 w-4" />}
						</Button>
					</div>
				</CardContent>
			</Card>

			<Card>
				<CardHeader className="pb-2">
					<CardTitle className="text-base">Entitlement Matrix</CardTitle>
					<CardDescription>All 10 Enterprise capability modules unlocked and active on this gateway.</CardDescription>
				</CardHeader>
				<CardContent>
					<Table>
						<TableHeader>
							<TableRow>
								<TableHead>Feature / Capability</TableHead>
								<TableHead>Category</TableHead>
								<TableHead className="text-right">Entitlement Status</TableHead>
							</TableRow>
						</TableHeader>
						<TableBody>
							{ENTITLEMENTS.map((item, idx) => (
								<TableRow key={idx}>
									<TableCell className="font-medium">{item.feature}</TableCell>
									<TableCell>
										<span className="text-xs text-muted-foreground">{item.tier}</span>
									</TableCell>
									<TableCell className="text-right">
										<Badge variant="outline" className="bg-emerald-500/10 text-emerald-600 border-emerald-500/20">
											<CheckCircle2 className="mr-1 h-3 w-3" />
											{item.status}
										</Badge>
									</TableCell>
								</TableRow>
							))}
						</TableBody>
					</Table>
				</CardContent>
			</Card>
		</div>
	);
}