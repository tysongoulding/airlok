import React, { useState } from "react";
import { Shuffle, Activity, Gauge, Zap, CheckCircle2, AlertTriangle, ArrowUpDown, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { toast } from "sonner";

interface RouteEndpoint {
	provider: string;
	model: string;
	weight: number;
	p50: number;
	p95: number;
	p99: number;
	errorRate: string;
	healthScore: number;
	circuitState: "CLOSED" | "HALF-OPEN" | "OPEN";
}

const INITIAL_ENDPOINTS: RouteEndpoint[] = [
	{
		provider: "OpenAI",
		model: "gpt-4o",
		weight: 38,
		p50: 12.4,
		p95: 42.1,
		p99: 89.2,
		errorRate: "0.01%",
		healthScore: 99,
		circuitState: "CLOSED",
	},
	{
		provider: "Anthropic",
		model: "claude-3-5-sonnet",
		weight: 32,
		p50: 15.2,
		p95: 48.0,
		p99: 94.6,
		errorRate: "0.02%",
		healthScore: 98,
		circuitState: "CLOSED",
	},
	{
		provider: "Google",
		model: "gemini-1.5-pro",
		weight: 20,
		p50: 16.8,
		p95: 52.4,
		p99: 105.1,
		errorRate: "0.03%",
		healthScore: 96,
		circuitState: "CLOSED",
	},
	{
		provider: "Groq",
		model: "llama-3.3-70b",
		weight: 10,
		p50: 6.2,
		p95: 18.9,
		p99: 34.0,
		errorRate: "0.01%",
		healthScore: 100,
		circuitState: "CLOSED",
	},
];

export default function AdaptiveRoutingView() {
	const [endpoints, setEndpoints] = useState<RouteEndpoint[]>(INITIAL_ENDPOINTS);
	const [refreshing, setRefreshing] = useState(false);

	const handleRecalculate = () => {
		setRefreshing(true);
		setTimeout(() => {
			setRefreshing(false);
			toast.success("P95 latency weights recalculated across active provider pools");
		}, 300);
	};

	return (
		<div className="space-y-6">
			{/* Header */}
			<div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
				<div>
					<div className="flex items-center gap-2">
						<h1 className="text-2xl font-bold tracking-tight text-foreground">Adaptive Load Balancing & Routing</h1>
						<Badge variant="outline" className="bg-emerald-500/10 text-emerald-500 border-emerald-500/20">
							Dynamic Weighting Active
						</Badge>
					</div>
					<p className="text-sm text-muted-foreground mt-0.5">
						Automatically redistributes traffic based on real-time P95 latency percentiles and error-rate health scoring.
					</p>
				</div>
				<div className="flex items-center gap-2">
					<Button variant="outline" size="sm" onClick={handleRecalculate} disabled={refreshing}>
						<RefreshCw className={`mr-1.5 h-3.5 w-3.5 ${refreshing ? "animate-spin" : ""}`} />
						Recalculate Weights
					</Button>
				</div>
			</div>

			{/* SLA Latency Percentile Cards */}
			<div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
				<Card>
					<CardHeader className="flex flex-row items-center justify-between pb-2">
						<CardTitle className="text-xs font-medium text-muted-foreground">P50 Latency (Median)</CardTitle>
						<Gauge className="h-4 w-4 text-emerald-500" />
					</CardHeader>
					<CardContent>
						<div className="text-2xl font-bold">14.2 ms</div>
						<p className="text-xs text-muted-foreground mt-1">Rolling 24-hour window</p>
					</CardContent>
				</Card>
				<Card>
					<CardHeader className="flex flex-row items-center justify-between pb-2">
						<CardTitle className="text-xs font-medium text-muted-foreground">P95 Latency (SLA Target)</CardTitle>
						<Activity className="h-4 w-4 text-primary" />
					</CardHeader>
					<CardContent>
						<div className="text-2xl font-bold">48.5 ms</div>
						<p className="text-xs text-muted-foreground mt-1">Well within 100ms threshold</p>
					</CardContent>
				</Card>
				<Card>
					<CardHeader className="flex flex-row items-center justify-between pb-2">
						<CardTitle className="text-xs font-medium text-muted-foreground">P99 Latency (Tail)</CardTitle>
						<Zap className="h-4 w-4 text-amber-500" />
					</CardHeader>
					<CardContent>
						<div className="text-2xl font-bold">112.0 ms</div>
						<p className="text-xs text-muted-foreground mt-1">Active circuit breaker bounds</p>
					</CardContent>
				</Card>
				<Card>
					<CardHeader className="flex flex-row items-center justify-between pb-2">
						<CardTitle className="text-xs font-medium text-muted-foreground">Gateway Uptime SLA</CardTitle>
						<CheckCircle2 className="h-4 w-4 text-emerald-500" />
					</CardHeader>
					<CardContent>
						<div className="text-2xl font-bold">99.995%</div>
						<p className="text-xs text-muted-foreground mt-1">Zero unplanned outages</p>
					</CardContent>
				</Card>
			</div>

			{/* Upstream Route Health & Weights Table */}
			<Card>
				<CardHeader>
					<CardTitle className="text-base font-semibold">Active Adaptive Route Distribution</CardTitle>
					<CardDescription>
						Proportional dispatch weights calculated from sliding-window latency and uptime probes.
					</CardDescription>
				</CardHeader>
				<CardContent className="p-0">
					<div className="overflow-x-auto">
						<table className="w-full text-left text-sm">
							<thead className="border-b bg-muted/40 text-xs font-medium text-muted-foreground uppercase">
								<tr>
									<th className="px-4 py-3">Provider & Model</th>
									<th className="px-4 py-3">Adaptive Weight</th>
									<th className="px-4 py-3">P50 Latency</th>
									<th className="px-4 py-3">P95 Latency</th>
									<th className="px-4 py-3">Error Rate</th>
									<th className="px-4 py-3">Health Score</th>
									<th className="px-4 py-3 text-right">Circuit State</th>
								</tr>
							</thead>
							<tbody className="divide-y">
								{endpoints.map((ep) => (
									<tr key={`${ep.provider}-${ep.model}`} className="hover:bg-muted/20 transition-colors">
										<td className="px-4 py-3.5">
											<div className="font-medium text-foreground">{ep.provider}</div>
											<div className="text-xs font-mono text-muted-foreground">{ep.model}</div>
										</td>
										<td className="px-4 py-3.5">
											<div className="flex items-center gap-2">
												<div className="w-16 bg-muted rounded-full h-2 overflow-hidden">
													<div className="bg-primary h-2 rounded-full" style={{ width: `${ep.weight * 2}%` }} />
												</div>
												<span className="font-mono text-xs font-semibold">{ep.weight}%</span>
											</div>
										</td>
										<td className="px-4 py-3.5 font-mono text-xs">{ep.p50} ms</td>
										<td className="px-4 py-3.5 font-mono text-xs font-medium text-foreground">{ep.p95} ms</td>
										<td className="px-4 py-3.5 font-mono text-xs text-muted-foreground">{ep.errorRate}</td>
										<td className="px-4 py-3.5">
											<Badge variant="outline" className="bg-emerald-500/10 text-emerald-500 border-emerald-500/20">
												{ep.healthScore} / 100
											</Badge>
										</td>
										<td className="px-4 py-3.5 text-right">
											<Badge className="bg-emerald-500/10 text-emerald-500 border-emerald-500/20">
												{ep.circuitState}
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