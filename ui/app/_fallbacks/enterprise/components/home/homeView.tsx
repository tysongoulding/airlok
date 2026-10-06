import React from "react";
import { House, KeyRound, Activity, ShieldCheck, Server, ArrowUpRight, CheckCircle2, Zap } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

export default function HomeView() {
	return (
		<div className="space-y-6">
			<div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b pb-4">
				<div className="flex items-center gap-3">
					<div className="flex h-12 w-12 items-center justify-center rounded-xl bg-primary/10 text-primary">
						<House className="h-6 w-6" />
					</div>
					<div>
						<div className="flex items-center gap-2">
							<h1 className="text-xl font-bold tracking-tight">SplitGate Workspace Overview</h1>
							<Badge variant="outline" className="bg-emerald-500/10 text-emerald-600 border-emerald-500/20">
								All Systems Normal
							</Badge>
						</div>
						<p className="text-sm text-muted-foreground">
							Personalized telemetry, allocated virtual keys, latency percentiles, and cluster status.
						</p>
					</div>
				</div>

				<div className="flex items-center gap-2">
					<Button size="sm" onClick={() => window.location.href = "/workspace/virtual-keys"}>
						<KeyRound className="mr-1.5 h-3.5 w-3.5" />
						Create Virtual Key
					</Button>
				</div>
			</div>

			<div className="grid grid-cols-1 md:grid-cols-4 gap-4">
				<Card className="bg-card/50">
					<CardHeader className="pb-2">
						<CardDescription className="text-xs">Active Virtual Keys</CardDescription>
						<CardTitle className="text-2xl font-bold flex items-center justify-between">
							4 Keys
							<KeyRound className="h-4 w-4 text-primary" />
						</CardTitle>
					</CardHeader>
					<CardContent className="text-xs text-muted-foreground">
						Scoped across 3 projects
					</CardContent>
				</Card>

				<Card className="bg-card/50">
					<CardHeader className="pb-2">
						<CardDescription className="text-xs">Monthly Spend / Quota</CardDescription>
						<CardTitle className="text-2xl font-bold flex items-center justify-between">
							$342.80
							<span className="text-xs font-normal text-muted-foreground">/ $2,000</span>
						</CardTitle>
					</CardHeader>
					<CardContent className="text-xs text-muted-foreground">
						17.1% of allocated budget consumed
					</CardContent>
				</Card>

				<Card className="bg-card/50">
					<CardHeader className="pb-2">
						<CardDescription className="text-xs">Avg Request Latency</CardDescription>
						<CardTitle className="text-2xl font-bold flex items-center justify-between">
							142 ms
							<Activity className="h-4 w-4 text-emerald-500" />
						</CardTitle>
					</CardHeader>
					<CardContent className="text-xs text-muted-foreground">
						P99: 410ms (Adaptive load balanced)
					</CardContent>
				</Card>

				<Card className="bg-card/50">
					<CardHeader className="pb-2">
						<CardDescription className="text-xs">Cluster Health</CardDescription>
						<CardTitle className="text-2xl font-bold flex items-center justify-between">
							4 / 4 Nodes
							<Server className="h-4 w-4 text-blue-500" />
						</CardTitle>
					</CardHeader>
					<CardContent className="text-xs text-muted-foreground">
						SWIM Gossip state synchronized
					</CardContent>
				</Card>
			</div>

			<div className="grid grid-cols-1 md:grid-cols-2 gap-6">
				<Card>
					<CardHeader className="pb-3">
						<CardTitle className="text-base">Upstream Providers Status</CardTitle>
						<CardDescription>Live routing metrics and health state across registered AI endpoints.</CardDescription>
					</CardHeader>
					<CardContent>
						<div className="space-y-3">
							{[
								{ name: "OpenAI", model: "gpt-4o", status: "Healthy", latency: "135ms", weight: "45%" },
								{ name: "Anthropic", model: "claude-3-5-sonnet", status: "Healthy", latency: "168ms", weight: "35%" },
								{ name: "Groq", model: "llama-3.3-70b", status: "Healthy", latency: "42ms", weight: "15%" },
								{ name: "AWS Bedrock", model: "amazon.titan", status: "Healthy", latency: "190ms", weight: "5%" },
							].map((p, idx) => (
								<div key={idx} className="flex items-center justify-between p-2.5 rounded-lg border bg-background/50">
									<div className="space-y-0.5">
										<div className="font-medium text-sm">{p.name}</div>
										<div className="text-xs font-mono text-muted-foreground">{p.model}</div>
									</div>
									<div className="flex items-center gap-3">
										<span className="text-xs text-muted-foreground">{p.latency}</span>
										<Badge variant="outline" className="bg-emerald-500/10 text-emerald-600 border-emerald-500/20 text-xs">
											{p.status}
										</Badge>
									</div>
								</div>
							))}
						</div>
					</CardContent>
				</Card>

				<Card>
					<CardHeader className="pb-3">
						<CardTitle className="text-base">Active Security & Guardrail Engines</CardTitle>
						<CardDescription>Real-time protection layers inspecting gateway traffic.</CardDescription>
					</CardHeader>
					<CardContent>
						<div className="space-y-3">
							{[
								{ name: "Native Heuristic & Regex Inspector", desc: "Secrets, API keys, and PII masking", state: "Enforcing" },
								{ name: "Microsoft Presidio Anonymizer", desc: "Entity extraction (SSN, IBAN, Credit Cards)", state: "Enforcing" },
								{ name: "Meta Llama Guard 3", desc: "Adversarial prompt injection & jailbreak defense", state: "Enforcing" },
								{ name: "Lakera AI Guardrail Engine", desc: "System prompt leak & data exfiltration protection", state: "Monitoring" },
							].map((g, idx) => (
								<div key={idx} className="flex items-center justify-between p-2.5 rounded-lg border bg-background/50">
									<div className="space-y-0.5">
										<div className="font-medium text-sm">{g.name}</div>
										<div className="text-xs text-muted-foreground">{g.desc}</div>
									</div>
									<Badge
										variant="outline"
										className={
											g.state === "Enforcing"
												? "bg-purple-500/10 text-purple-600 border-purple-500/20 text-xs"
												: "bg-blue-500/10 text-blue-600 border-blue-500/20 text-xs"
										}
									>
										{g.state}
									</Badge>
								</div>
							))}
						</div>
					</CardContent>
				</Card>
			</div>
		</div>
	);
}