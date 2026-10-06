import React, { useState } from "react";
import { Network, Server, Cpu, Activity, RefreshCw, Zap, ShieldCheck, ArrowRightLeft } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { toast } from "sonner";

interface ClusterNode {
	id: string;
	address: string;
	role: "Coordinator (Leader)" | "Worker Node";
	status: "Alive" | "Suspect" | "Leaving";
	rttPing: string;
	uptime: string;
	cpuUsage: string;
	memoryUsage: string;
	rateLimitSyncs: number;
}

const NODES: ClusterNode[] = [
	{
		id: "splitgate-primary-01",
		address: "192.168.144.110:8080",
		role: "Coordinator (Leader)",
		status: "Alive",
		rttPing: "0.2ms",
		uptime: "99.995%",
		cpuUsage: "3.4%",
		memoryUsage: "48.2 MB",
		rateLimitSyncs: 14820,
	},
	{
		id: "splitgate-worker-02",
		address: "192.168.144.111:8080",
		role: "Worker Node",
		status: "Alive",
		rttPing: "0.6ms",
		uptime: "99.991%",
		cpuUsage: "2.8%",
		memoryUsage: "44.6 MB",
		rateLimitSyncs: 12104,
	},
	{
		id: "splitgate-worker-03",
		address: "192.168.144.112:8080",
		role: "Worker Node",
		status: "Alive",
		rttPing: "0.5ms",
		uptime: "99.993%",
		cpuUsage: "3.1%",
		memoryUsage: "45.1 MB",
		rateLimitSyncs: 13490,
	},
];

export default function ClusterView() {
	const [nodes, setNodes] = useState<ClusterNode[]>(NODES);
	const [refreshing, setRefreshing] = useState(false);

	const handleRefresh = () => {
		setRefreshing(true);
		setTimeout(() => {
			setRefreshing(false);
			toast.success("Cluster gossip topology synchronized (3 nodes responsive)");
		}, 400);
	};

	return (
		<div className="space-y-6">
			{/* Header */}
			<div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
				<div>
					<div className="flex items-center gap-2">
						<h1 className="text-2xl font-bold tracking-tight text-foreground">Cluster Topology & Memberlist</h1>
						<Badge variant="outline" className="bg-emerald-500/10 text-emerald-500 border-emerald-500/20">
							Active & Balanced
						</Badge>
					</div>
					<p className="text-sm text-muted-foreground mt-0.5">
						Gossip protocol membership, distributed P2P rate limiting, and broker message relays.
					</p>
				</div>
				<div className="flex items-center gap-2">
					<Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
						<RefreshCw className={`mr-1.5 h-3.5 w-3.5 ${refreshing ? "animate-spin" : ""}`} />
						Refresh Topology
					</Button>
					<Button size="sm" onClick={() => toast.success("Distributed rate limit cache rebalanced")}>
						<ArrowRightLeft className="mr-1.5 h-3.5 w-3.5" />
						Rebalance Sync
					</Button>
				</div>
			</div>

			{/* Cluster Stat Cards */}
			<div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
				<Card>
					<CardHeader className="flex flex-row items-center justify-between pb-2">
						<CardTitle className="text-xs font-medium text-muted-foreground">Cluster Protocol</CardTitle>
						<Network className="h-4 w-4 text-emerald-500" />
					</CardHeader>
					<CardContent>
						<div className="text-2xl font-bold">Gossip Mesh</div>
						<p className="text-xs text-muted-foreground mt-1">P2P Memberlist + gRPC Sync</p>
					</CardContent>
				</Card>
				<Card>
					<CardHeader className="flex flex-row items-center justify-between pb-2">
						<CardTitle className="text-xs font-medium text-muted-foreground">Healthy Nodes</CardTitle>
						<Server className="h-4 w-4 text-primary" />
					</CardHeader>
					<CardContent>
						<div className="text-2xl font-bold">{nodes.length} Active</div>
						<p className="text-xs text-muted-foreground mt-1">0 suspect, 0 unreachable</p>
					</CardContent>
				</Card>
				<Card>
					<CardHeader className="flex flex-row items-center justify-between pb-2">
						<CardTitle className="text-xs font-medium text-muted-foreground">P2P Sync Rate</CardTitle>
						<Activity className="h-4 w-4 text-blue-500" />
					</CardHeader>
					<CardContent>
						<div className="text-2xl font-bold">1,420 / sec</div>
						<p className="text-xs text-muted-foreground mt-1">Distributed token bucket sync</p>
					</CardContent>
				</Card>
				<Card>
					<CardHeader className="flex flex-row items-center justify-between pb-2">
						<CardTitle className="text-xs font-medium text-muted-foreground">Broker Message Relay</CardTitle>
						<Zap className="h-4 w-4 text-amber-500" />
					</CardHeader>
					<CardContent>
						<div className="text-2xl font-bold">0 Dropped</div>
						<p className="text-xs text-muted-foreground mt-1">100% broadcast delivery</p>
					</CardContent>
				</Card>
			</div>

			{/* Nodes Table */}
			<Card>
				<CardHeader>
					<CardTitle className="text-base font-semibold">Active Cluster Member Nodes</CardTitle>
					<CardDescription>
						All online gateways communicating through gossip protocol heartbeats and synchronized token buckets.
					</CardDescription>
				</CardHeader>
				<CardContent className="p-0">
					<div className="overflow-x-auto">
						<table className="w-full text-left text-sm">
							<thead className="border-b bg-muted/40 text-xs font-medium text-muted-foreground uppercase">
								<tr>
									<th className="px-4 py-3">Node ID</th>
									<th className="px-4 py-3">Host & Port</th>
									<th className="px-4 py-3">Cluster Role</th>
									<th className="px-4 py-3">Status</th>
									<th className="px-4 py-3">RTT Ping</th>
									<th className="px-4 py-3">Resources</th>
									<th className="px-4 py-3 text-right">Rate Limit Syncs</th>
								</tr>
							</thead>
							<tbody className="divide-y">
								{nodes.map((node) => (
									<tr key={node.id} className="hover:bg-muted/20 transition-colors">
										<td className="px-4 py-3.5 font-medium text-foreground">
											{node.id}
										</td>
										<td className="px-4 py-3.5 font-mono text-xs text-muted-foreground">
											{node.address}
										</td>
										<td className="px-4 py-3.5">
											<Badge
												variant="outline"
												className={
													node.role.includes("Leader")
														? "bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20"
														: ""
												}
											>
												{node.role}
											</Badge>
										</td>
										<td className="px-4 py-3.5">
											<Badge className="bg-emerald-500/10 text-emerald-500 border-emerald-500/20">
												{node.status}
											</Badge>
										</td>
										<td className="px-4 py-3.5 font-mono text-xs">{node.rttPing}</td>
										<td className="px-4 py-3.5 text-xs text-muted-foreground">
											CPU: {node.cpuUsage} | RAM: {node.memoryUsage}
										</td>
										<td className="px-4 py-3.5 text-right font-mono text-xs">
											{node.rateLimitSyncs.toLocaleString()}
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