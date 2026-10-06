import React, { useState } from "react";
import { Siren, Plus, CheckCircle2, AlertTriangle, Bell, Clock, ShieldAlert, Zap, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { toast } from "sonner";

interface AlertRule {
	id: string;
	name: string;
	metric: string;
	condition: string;
	threshold: string;
	window: string;
	severity: "critical" | "warning" | "info";
	channels: string[];
	enabled: boolean;
}

const INITIAL_RULES: AlertRule[] = [
	{
		id: "rule-1",
		name: "High Provider Latency P99",
		metric: "upstream_request_duration_ms",
		condition: "P99 >",
		threshold: "2500ms",
		window: "5m",
		severity: "warning",
		channels: ["Slack #platform-alerts", "Email SRE"],
		enabled: true,
	},
	{
		id: "rule-2",
		name: "Provider 5xx Error Burst",
		metric: "http_status_5xx_rate",
		condition: "Rate >",
		threshold: "3.0%",
		window: "2m",
		severity: "critical",
		channels: ["PagerDuty Sev1", "Slack #platform-alerts"],
		enabled: true,
	},
	{
		id: "rule-3",
		name: "Virtual Key Budget Depletion",
		metric: "virtual_key_spend_pct",
		condition: "Spend >=",
		threshold: "85%",
		window: "1m",
		severity: "warning",
		channels: ["Slack #platform-alerts"],
		enabled: true,
	},
	{
		id: "rule-4",
		name: "Guardrail Injection Attack Spikes",
		metric: "guardrail_violation_count",
		condition: "Count >",
		threshold: "10 violations",
		window: "1m",
		severity: "critical",
		channels: ["PagerDuty Sev1", "Slack #security-soc"],
		enabled: true,
	},
	{
		id: "rule-5",
		name: "Circuit Breaker Trip Event",
		metric: "circuit_breaker_state_changes",
		condition: "State ==",
		threshold: "OPEN",
		window: "Immediate",
		severity: "critical",
		channels: ["PagerDuty Sev1", "Slack #platform-alerts"],
		enabled: true,
	},
];

export default function AlertRulesView() {
	const [rules, setRules] = useState<AlertRule[]>(INITIAL_RULES);
	const [isAdding, setIsAdding] = useState(false);
	const [newRuleName, setNewRuleName] = useState("");
	const [newRuleThreshold, setNewRuleThreshold] = useState("");

	const toggleRule = (id: string) => {
		setRules((prev) =>
			prev.map((r) => {
				if (r.id === id) {
					const next = !r.enabled;
					toast.success(`${r.name} is now ${next ? "enabled" : "disabled"}`);
					return { ...r, enabled: next };
				}
				return r;
			})
		);
	};

	const handleAddRule = () => {
		if (!newRuleName) {
			toast.error("Please provide a rule name");
			return;
		}
		const newRule: AlertRule = {
			id: `rule-${Date.now()}`,
			name: newRuleName,
			metric: "custom_evaluator_metric",
			condition: "Value >",
			threshold: newRuleThreshold || "100",
			window: "5m",
			severity: "warning",
			channels: ["Slack #platform-alerts"],
			enabled: true,
		};
		setRules([...rules, newRule]);
		setNewRuleName("");
		setNewRuleThreshold("");
		setIsAdding(false);
		toast.success(`Created alert rule: ${newRuleName}`);
	};

	return (
		<div className="space-y-6">
			<div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b pb-4">
				<div className="flex items-center gap-3">
					<div className="flex h-12 w-12 items-center justify-center rounded-xl bg-red-500/10 text-red-600 dark:text-red-400">
						<Siren className="h-6 w-6" />
					</div>
					<div>
						<div className="flex items-center gap-2">
							<h1 className="text-xl font-bold tracking-tight">SplitGate Alerting Rules</h1>
							<Badge variant="outline" className="bg-emerald-500/10 text-emerald-600 border-emerald-500/20">
								{rules.filter((r) => r.enabled).length} Rules Active
							</Badge>
						</div>
						<p className="text-sm text-muted-foreground">
							Define real-time detection rules to proactively trigger notifications on latency spikes, error bursts, or budget limits.
						</p>
					</div>
				</div>

				<Button onClick={() => setIsAdding(!isAdding)}>
					<Plus className="mr-1.5 h-4 w-4" />
					New Alert Rule
				</Button>
			</div>

			{isAdding && (
				<Card className="border-primary/40 bg-accent/20">
					<CardHeader className="pb-3">
						<CardTitle className="text-base">Create Notification Rule</CardTitle>
						<CardDescription>Configure an evaluation condition against real-time gateway metrics.</CardDescription>
					</CardHeader>
					<CardContent className="space-y-4">
						<div className="grid grid-cols-1 md:grid-cols-2 gap-4">
							<div className="space-y-1.5">
								<label className="text-xs font-semibold text-muted-foreground">Rule Name</label>
								<Input
									placeholder="e.g. Rate Limit Exhaustion Watcher"
									value={newRuleName}
									onChange={(e) => setNewRuleName(e.target.value)}
								/>
							</div>
							<div className="space-y-1.5">
								<label className="text-xs font-semibold text-muted-foreground">Threshold Trigger</label>
								<Input
									placeholder="e.g. > 90% or > 5000ms"
									value={newRuleThreshold}
									onChange={(e) => setNewRuleThreshold(e.target.value)}
								/>
							</div>
						</div>
						<div className="flex justify-end gap-2">
							<Button variant="outline" size="sm" onClick={() => setIsAdding(false)}>
								Cancel
							</Button>
							<Button size="sm" onClick={handleAddRule}>
								Save Rule
							</Button>
						</div>
					</CardContent>
				</Card>
			)}

			<Card>
				<CardHeader className="pb-2">
					<CardTitle className="text-base">Configured Detection Rules</CardTitle>
				</CardHeader>
				<CardContent>
					<Table>
						<TableHeader>
							<TableRow>
								<TableHead>Rule Name</TableHead>
								<TableHead>Metric & Condition</TableHead>
								<TableHead>Window</TableHead>
								<TableHead>Severity</TableHead>
								<TableHead>Notification Channels</TableHead>
								<TableHead className="text-right">Enabled</TableHead>
							</TableRow>
						</TableHeader>
						<TableBody>
							{rules.map((rule) => (
								<TableRow key={rule.id}>
									<TableCell className="font-medium">
										<div className="flex items-center gap-2">
											<Bell className="h-4 w-4 text-muted-foreground" />
											{rule.name}
										</div>
									</TableCell>
									<TableCell>
										<code className="text-xs bg-muted px-1.5 py-0.5 rounded font-mono">
											{rule.condition} {rule.threshold}
										</code>
									</TableCell>
									<TableCell className="text-muted-foreground text-xs">{rule.window}</TableCell>
									<TableCell>
										<Badge
											variant="outline"
											className={
												rule.severity === "critical"
													? "bg-red-500/10 text-red-600 border-red-500/20"
													: "bg-amber-500/10 text-amber-600 border-amber-500/20"
											}
										>
											{rule.severity.toUpperCase()}
										</Badge>
									</TableCell>
									<TableCell>
										<div className="flex flex-wrap gap-1">
											{rule.channels.map((ch) => (
												<span key={ch} className="inline-block rounded bg-secondary px-1.5 py-0.5 text-[11px]">
													{ch}
												</span>
											))}
										</div>
									</TableCell>
									<TableCell className="text-right">
										<Switch checked={rule.enabled} onCheckedChange={() => toggleRule(rule.id)} />
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