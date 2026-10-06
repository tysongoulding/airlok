import React, { useState } from "react";
import { Zap, ShieldCheck, AlertTriangle, RefreshCw, CheckCircle2, RotateCcw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { toast } from "sonner";

interface BreakerRule {
	id: string;
	provider: string;
	errorThreshold: string;
	windowDuration: string;
	resetTimeout: string;
	state: "CLOSED" | "HALF-OPEN" | "OPEN";
	trippedCount: number;
	fallbackProvider: string;
}

const INITIAL_BREAKERS: BreakerRule[] = [
	{
		id: "cb-openai",
		provider: "OpenAI Primary Pool",
		errorThreshold: "5 consecutive 5xx or >15% error rate",
		windowDuration: "30s",
		resetTimeout: "60s",
		state: "CLOSED",
		trippedCount: 0,
		fallbackProvider: "Anthropic claude-3-5-sonnet",
	},
	{
		id: "cb-anthropic",
		provider: "Anthropic Primary Pool",
		errorThreshold: "5 consecutive 5xx or >15% error rate",
		windowDuration: "30s",
		resetTimeout: "60s",
		state: "CLOSED",
		trippedCount: 0,
		fallbackProvider: "Google gemini-1.5-pro",
	},
	{
		id: "cb-gemini",
		provider: "Google Gemini Pool",
		errorThreshold: "5 consecutive 5xx or >20% error rate",
		windowDuration: "30s",
		resetTimeout: "45s",
		state: "CLOSED",
		trippedCount: 0,
		fallbackProvider: "Groq llama-3.3-70b",
	},
	{
		id: "cb-bedrock",
		provider: "AWS Bedrock Mantle",
		errorThreshold: "3 consecutive 5xx or >10% error rate",
		windowDuration: "20s",
		resetTimeout: "60s",
		state: "CLOSED",
		trippedCount: 0,
		fallbackProvider: "OpenAI gpt-4o",
	},
];

export default function CircuitBreakerView() {
	const [breakers, setBreakers] = useState<BreakerRule[]>(INITIAL_BREAKERS);

	const resetAllBreakers = () => {
		setBreakers((prev) =>
			prev.map((b) => ({ ...b, state: "CLOSED" as const }))
		);
		toast.success("All circuit breakers reset to CLOSED (Healthy)");
	};

	return (
		<div className="space-y-6">
			{/* Header */}
			<div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
				<div>
					<div className="flex items-center gap-2">
						<h1 className="text-2xl font-bold tracking-tight text-foreground">Circuit Breakers & Automatic Failover</h1>
						<Badge variant="outline" className="bg-emerald-500/10 text-emerald-500 border-emerald-500/20">
							Active Protection
						</Badge>
					</div>
					<p className="text-sm text-muted-foreground mt-0.5">
						Automatically shifts traffic away from failing upstream providers to prevent application degradation.
					</p>
				</div>
				<div className="flex items-center gap-2">
					<Button variant="outline" size="sm" onClick={resetAllBreakers}>
						<RotateCcw className="mr-1.5 h-3.5 w-3.5" />
						Reset All Breakers
					</Button>
				</div>
			</div>

			{/* Metric Cards */}
			<div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
				<Card>
					<CardHeader className="flex flex-row items-center justify-between pb-2">
						<CardTitle className="text-xs font-medium text-muted-foreground">Monitored Upstreams</CardTitle>
						<Zap className="h-4 w-4 text-primary" />
					</CardHeader>
					<CardContent>
						<div className="text-2xl font-bold">{breakers.length} Endpoints</div>
						<p className="text-xs text-muted-foreground mt-1">Real-time sliding window telemetry</p>
					</CardContent>
				</Card>
				<Card>
					<CardHeader className="flex flex-row items-center justify-between pb-2">
						<CardTitle className="text-xs font-medium text-muted-foreground">Active Trips</CardTitle>
						<ShieldCheck className="h-4 w-4 text-emerald-500" />
					</CardHeader>
					<CardContent>
						<div className="text-2xl font-bold">0 Tripped</div>
						<p className="text-xs text-muted-foreground mt-1">All upstreams operational</p>
					</CardContent>
				</Card>
				<Card>
					<CardHeader className="flex flex-row items-center justify-between pb-2">
						<CardTitle className="text-xs font-medium text-muted-foreground">Auto-Recovery Probes</CardTitle>
						<CheckCircle2 className="h-4 w-4 text-blue-500" />
					</CardHeader>
					<CardContent>
						<div className="text-2xl font-bold">Every 5s</div>
						<p className="text-xs text-muted-foreground mt-1">Exponential backoff recovery probe</p>
					</CardContent>
				</Card>
				<Card>
					<CardHeader className="flex flex-row items-center justify-between pb-2">
						<CardTitle className="text-xs font-medium text-muted-foreground">Failover Reliability</CardTitle>
						<ShieldCheck className="h-4 w-4 text-emerald-500" />
					</CardHeader>
					<CardContent>
						<div className="text-2xl font-bold">100%</div>
						<p className="text-xs text-muted-foreground mt-1">Zero dropped inference calls</p>
					</CardContent>
				</Card>
			</div>

			{/* Breakers Table */}
			<Card>
				<CardHeader>
					<CardTitle className="text-base font-semibold">Configured Upstream Circuit Breakers</CardTitle>
					<CardDescription>
						Failure condition thresholds and designated fallback destinations.
					</CardDescription>
				</CardHeader>
				<CardContent className="p-0">
					<div className="overflow-x-auto">
						<table className="w-full text-left text-sm">
							<thead className="border-b bg-muted/40 text-xs font-medium text-muted-foreground uppercase">
								<tr>
									<th className="px-4 py-3">Upstream Provider</th>
									<th className="px-4 py-3">Trip Threshold</th>
									<th className="px-4 py-3">Evaluation Window</th>
									<th className="px-4 py-3">Reset Cooldown</th>
									<th className="px-4 py-3">Automatic Fallback</th>
									<th className="px-4 py-3 text-right">Circuit State</th>
								</tr>
							</thead>
							<tbody className="divide-y">
								{breakers.map((b) => (
									<tr key={b.id} className="hover:bg-muted/20 transition-colors">
										<td className="px-4 py-3.5 font-medium text-foreground">
											{b.provider}
										</td>
										<td className="px-4 py-3.5 text-xs text-muted-foreground">
											{b.errorThreshold}
										</td>
										<td className="px-4 py-3.5 font-mono text-xs">{b.windowDuration}</td>
										<td className="px-4 py-3.5 font-mono text-xs">{b.resetTimeout}</td>
										<td className="px-4 py-3.5 font-mono text-xs text-primary">
											{b.fallbackProvider}
										</td>
										<td className="px-4 py-3.5 text-right">
											<Badge className="bg-emerald-500/10 text-emerald-500 border-emerald-500/20">
												{b.state}
											</Badge>
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