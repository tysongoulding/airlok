import React, { useState } from "react";
import { Bell, Plus, CheckCircle2, RefreshCw, Send, MessageSquare, Mail, Zap, ExternalLink } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { toast } from "sonner";

interface AlertChannel {
	id: string;
	name: string;
	type: "slack" | "pagerduty" | "email" | "webhook";
	target: string;
	status: "healthy" | "unverified";
	enabled: boolean;
}

const INITIAL_CHANNELS: AlertChannel[] = [
	{
		id: "ch-1",
		name: "Slack #platform-alerts",
		type: "slack",
		target: "https://hooks.slack.com/services/T00/B00/XXXXXX",
		status: "healthy",
		enabled: true,
	},
	{
		id: "ch-2",
		name: "PagerDuty Sev-1 Incident Escalation",
		type: "pagerduty",
		target: "pd-service-key-splitgate-mission-critical",
		status: "healthy",
		enabled: true,
	},
	{
		id: "ch-3",
		name: "Platform SRE Email Distribution",
		type: "email",
		target: "sre-core-oncall@splitgate.internal",
		status: "healthy",
		enabled: true,
	},
	{
		id: "ch-4",
		name: "Security SOC Discord Relay",
		type: "webhook",
		target: "https://discord.com/api/webhooks/12345/abcdef",
		status: "healthy",
		enabled: true,
	},
];

export default function AlertChannelsView() {
	const [channels, setChannels] = useState<AlertChannel[]>(INITIAL_CHANNELS);
	const [testingId, setTestingId] = useState<string | null>(null);

	const handleTest = (channel: AlertChannel) => {
		setTestingId(channel.id);
		setTimeout(() => {
			setTestingId(null);
			toast.success(`Dispatched simulated test alert payload to ${channel.name}!`);
		}, 600);
	};

	const toggleChannel = (id: string) => {
		setChannels((prev) =>
			prev.map((c) => {
				if (c.id === id) {
					const next = !c.enabled;
					toast.success(`${c.name} is now ${next ? "active" : "muted"}`);
					return { ...c, enabled: next };
				}
				return c;
			})
		);
	};

	return (
		<div className="space-y-6">
			<div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b pb-4">
				<div className="flex items-center gap-3">
					<div className="flex h-12 w-12 items-center justify-center rounded-xl bg-blue-500/10 text-blue-600 dark:text-blue-400">
						<Bell className="h-6 w-6" />
					</div>
					<div>
						<div className="flex items-center gap-2">
							<h1 className="text-xl font-bold tracking-tight">Notification Channels</h1>
							<Badge variant="outline" className="bg-emerald-500/10 text-emerald-600 border-emerald-500/20">
								{channels.filter((c) => c.enabled).length} Active Channels
							</Badge>
						</div>
						<p className="text-sm text-muted-foreground">
							Connect communication endpoints where SplitGate gateway anomalies and SLO violations will dispatch.
						</p>
					</div>
				</div>

				<Button onClick={() => toast.info("New channel configuration dialog opened.")}>
					<Plus className="mr-1.5 h-4 w-4" />
					Add Channel
				</Button>
			</div>

			<div className="grid grid-cols-1 md:grid-cols-2 gap-4">
				{channels.map((channel) => (
					<Card key={channel.id} className="relative overflow-hidden">
						<CardHeader className="pb-3 flex flex-row items-start justify-between">
							<div className="space-y-1">
								<CardTitle className="text-base flex items-center gap-2">
									{channel.type === "slack" && <MessageSquare className="h-4 w-4 text-emerald-500" />}
									{channel.type === "pagerduty" && <Zap className="h-4 w-4 text-red-500" />}
									{channel.type === "email" && <Mail className="h-4 w-4 text-blue-500" />}
									{channel.type === "webhook" && <ExternalLink className="h-4 w-4 text-purple-500" />}
									{channel.name}
								</CardTitle>
								<CardDescription className="text-xs font-mono truncate max-w-[280px]">
									{channel.target}
								</CardDescription>
							</div>
							<Switch checked={channel.enabled} onCheckedChange={() => toggleChannel(channel.id)} />
						</CardHeader>
						<CardContent className="pt-0 flex items-center justify-between">
							<div className="flex items-center gap-1.5 text-xs text-emerald-600 font-medium">
								<CheckCircle2 className="h-3.5 w-3.5" />
								Healthy & Verified
							</div>
							<Button
								variant="outline"
								size="sm"
								className="h-8 text-xs"
								onClick={() => handleTest(channel)}
								disabled={testingId === channel.id || !channel.enabled}
							>
								{testingId === channel.id ? (
									<RefreshCw className="mr-1 h-3 w-3 animate-spin" />
								) : (
									<Send className="mr-1 h-3 w-3" />
								)}
								Send Test
							</Button>
						</CardContent>
					</Card>
				))}
			</div>
		</div>
	);
}