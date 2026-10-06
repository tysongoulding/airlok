import React, { useState } from "react";
import { History, ShieldAlert, CheckCircle2, Clock, Filter, AlertTriangle, ArrowUpRight } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

interface AlertIncident {
	id: string;
	timestamp: string;
	ruleName: string;
	severity: "critical" | "warning";
	triggerValue: string;
	duration: string;
	targetChannel: string;
	status: "Resolved" | "Investigating";
}

const INCIDENTS: AlertIncident[] = [
	{
		id: "inc-1092",
		timestamp: "10 mins ago",
		ruleName: "High Provider Latency P99",
		severity: "warning",
		triggerValue: "Latency reached 3120ms (Threshold: 2500ms)",
		duration: "3m 40s",
		targetChannel: "Slack #platform-alerts",
		status: "Resolved",
	},
	{
		id: "inc-1088",
		timestamp: "1 hour ago",
		ruleName: "Guardrail Injection Attack Spikes",
		severity: "critical",
		triggerValue: "14 violations detected in 60s window",
		duration: "1m 15s",
		targetChannel: "PagerDuty Sev1, Slack #security-soc",
		status: "Resolved",
	},
	{
		id: "inc-1074",
		timestamp: "3 hours ago",
		ruleName: "Provider 5xx Error Burst",
		severity: "critical",
		triggerValue: "Anthropic claude-3-5-sonnet HTTP 529 overload",
		duration: "4m 20s",
		targetChannel: "PagerDuty Sev1",
		status: "Resolved",
	},
	{
		id: "inc-1051",
		timestamp: "Yesterday, 18:22",
		ruleName: "Virtual Key Budget Depletion",
		severity: "warning",
		triggerValue: "Virtual Key 'vk_research_team' exceeded 85% cap",
		duration: "Persistent",
		targetChannel: "Slack #platform-alerts",
		status: "Resolved",
	},
];

export default function AlertHistoryView() {
	const [search, setSearch] = useState("");

	const filtered = INCIDENTS.filter(
		(inc) =>
			inc.ruleName.toLowerCase().includes(search.toLowerCase()) ||
			inc.triggerValue.toLowerCase().includes(search.toLowerCase())
	);

	return (
		<div className="space-y-6">
			<div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b pb-4">
				<div className="flex items-center gap-3">
					<div className="flex h-12 w-12 items-center justify-center rounded-xl bg-amber-500/10 text-amber-600 dark:text-amber-400">
						<History className="h-6 w-6" />
					</div>
					<div>
						<div className="flex items-center gap-2">
							<h1 className="text-xl font-bold tracking-tight">Alert Incident History</h1>
							<Badge variant="outline" className="bg-emerald-500/10 text-emerald-600 border-emerald-500/20">
								All Incidents Resolved
							</Badge>
						</div>
						<p className="text-sm text-muted-foreground">
							Audit log of past gateway alert firings, threshold triggers, durations, and resolution timestamps.
						</p>
					</div>
				</div>

				<div className="w-full sm:w-72">
					<Input
						placeholder="Search past alert events..."
						value={search}
						onChange={(e) => setSearch(e.target.value)}
					/>
				</div>
			</div>

			<Card>
				<CardHeader className="pb-2">
					<CardTitle className="text-base">Historical Incident Log</CardTitle>
				</CardHeader>
				<CardContent>
					<Table>
						<TableHeader>
							<TableRow>
								<TableHead>Time</TableHead>
								<TableHead>Rule Name</TableHead>
								<TableHead>Severity</TableHead>
								<TableHead>Trigger Context</TableHead>
								<TableHead>Duration</TableHead>
								<TableHead>Channel</TableHead>
								<TableHead className="text-right">Status</TableHead>
							</TableRow>
						</TableHeader>
						<TableBody>
							{filtered.map((inc) => (
								<TableRow key={inc.id}>
									<TableCell className="text-xs text-muted-foreground whitespace-nowrap">{inc.timestamp}</TableCell>
									<TableCell className="font-medium">{inc.ruleName}</TableCell>
									<TableCell>
										<Badge
											variant="outline"
											className={
												inc.severity === "critical"
													? "bg-red-500/10 text-red-600 border-red-500/20"
													: "bg-amber-500/10 text-amber-600 border-amber-500/20"
											}
										>
											{inc.severity.toUpperCase()}
										</Badge>
									</TableCell>
									<TableCell className="text-xs font-mono text-muted-foreground max-w-[300px] truncate">
										{inc.triggerValue}
									</TableCell>
									<TableCell className="text-xs text-muted-foreground">{inc.duration}</TableCell>
									<TableCell className="text-xs text-muted-foreground">{inc.targetChannel}</TableCell>
									<TableCell className="text-right">
										<Badge variant="outline" className="bg-emerald-500/10 text-emerald-600 border-emerald-500/20">
											<CheckCircle2 className="mr-1 h-3 w-3" />
											{inc.status}
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