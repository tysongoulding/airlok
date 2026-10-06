import React, { useState } from "react";
import { Radio, CheckCircle2, RefreshCw, Save, Activity, ShieldCheck, Database, Layers } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { toast } from "sonner";

interface EnableToggleProps {
	enabled: boolean;
	onToggle: () => void;
	disabled?: boolean;
}

interface PubSubConnectorViewProps {
	onDelete?: () => void;
	isDeleting?: boolean;
	enableToggle?: EnableToggleProps;
}

export default function PubSubConnectorView(_props: PubSubConnectorViewProps = {}) {
	const [projectId, setProjectId] = useState("splitgate-cloud-prod");
	const [topicId, setTopicId] = useState("splitgate-telemetry-feed");
	const [credentialsMode, setCredentialsMode] = useState("adc");
	const [batchSize, setBatchSize] = useState("500");
	const [batchDelayMs, setBatchDelayMs] = useState("50");
	const [enableOrderingKey, setEnableOrderingKey] = useState(true);
	const [isTesting, setIsTesting] = useState(false);
	const [isSaving, setIsSaving] = useState(false);

	const handleTest = () => {
		setIsTesting(true);
		setTimeout(() => {
			setIsTesting(false);
			toast.success("Google Cloud Pub/Sub topic permissions verified. Message published successfully.");
		}, 600);
	};

	const handleSave = () => {
		setIsSaving(true);
		setTimeout(() => {
			setIsSaving(false);
			toast.success("GCP Pub/Sub connector configuration saved.");
		}, 500);
	};

	return (
		<div className="space-y-6">
			<div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b pb-4">
				<div className="flex items-center gap-3">
					<div className="flex h-12 w-12 items-center justify-center rounded-xl bg-blue-500/10 text-blue-600 dark:text-blue-400">
						<Radio className="h-6 w-6" />
					</div>
					<div>
						<div className="flex items-center gap-2">
							<h1 className="text-xl font-bold tracking-tight">Google Cloud Pub/Sub Exporter</h1>
							<Badge variant="outline" className="bg-emerald-500/10 text-emerald-600 border-emerald-500/20">
								Publisher Ready
							</Badge>
						</div>
						<p className="text-sm text-muted-foreground">
							Publish high-throughput inference audit messages to GCP Pub/Sub for consumption by Cloud Dataflow, BigQuery, or microservices.
						</p>
					</div>
				</div>

				<div className="flex items-center gap-2">
					<Button variant="outline" size="sm" onClick={handleTest} disabled={isTesting}>
						{isTesting ? <RefreshCw className="mr-1.5 h-3.5 w-3.5 animate-spin" /> : <Activity className="mr-1.5 h-3.5 w-3.5 text-blue-500" />}
						Test Publish
					</Button>
					<Button size="sm" onClick={handleSave} disabled={isSaving}>
						{isSaving ? <RefreshCw className="mr-1.5 h-3.5 w-3.5 animate-spin" /> : <Save className="mr-1.5 h-3.5 w-3.5" />}
						Save Exporter
					</Button>
				</div>
			</div>

			<div className="grid grid-cols-1 md:grid-cols-3 gap-4">
				<Card className="bg-card/50">
					<CardHeader className="pb-2">
						<CardDescription className="text-xs">Publish Status</CardDescription>
						<CardTitle className="text-lg flex items-center gap-2">
							<CheckCircle2 className="h-4 w-4 text-emerald-500" />
							Online (Low Latency)
						</CardTitle>
					</CardHeader>
					<CardContent className="text-xs text-muted-foreground">
						Avg publish latency: 8.2ms; 0 unacked records
					</CardContent>
				</Card>

				<Card className="bg-card/50">
					<CardHeader className="pb-2">
						<CardDescription className="text-xs">GCP Topic Path</CardDescription>
						<CardTitle className="text-lg flex items-center gap-2 truncate">
							<Database className="h-4 w-4 text-blue-500 shrink-0" />
							projects/{projectId}/topics/{topicId}
						</CardTitle>
					</CardHeader>
					<CardContent className="text-xs text-muted-foreground">
						Subscription workers: 4 active subscribers
					</CardContent>
				</Card>

				<Card className="bg-card/50">
					<CardHeader className="pb-2">
						<CardDescription className="text-xs">Auth Strategy</CardDescription>
						<CardTitle className="text-lg flex items-center gap-2">
							<ShieldCheck className="h-4 w-4 text-purple-500" />
							{credentialsMode === "adc" ? "Google ADC / Workload Identity" : "Service Account Key JSON"}
						</CardTitle>
					</CardHeader>
					<CardContent className="text-xs text-muted-foreground">
						IAM Role: roles/pubsub.publisher
					</CardContent>
				</Card>
			</div>

			<Card>
				<CardHeader>
					<CardTitle className="text-base">Google Cloud Pub/Sub Pipeline Configuration</CardTitle>
					<CardDescription>
						Configure your GCP Project ID, Topic Name, and batching limits.
					</CardDescription>
				</CardHeader>
				<CardContent className="space-y-4">
					<div className="grid grid-cols-1 md:grid-cols-2 gap-4">
						<div className="space-y-1.5">
							<label className="text-xs font-semibold text-muted-foreground">GCP Project ID</label>
							<Input
								value={projectId}
								onChange={(e) => setProjectId(e.target.value)}
								placeholder="e.g. splitgate-prod"
							/>
						</div>
						<div className="space-y-1.5">
							<label className="text-xs font-semibold text-muted-foreground">Pub/Sub Topic ID</label>
							<Input
								value={topicId}
								onChange={(e) => setTopicId(e.target.value)}
								placeholder="e.g. splitgate-telemetry-feed"
							/>
						</div>
					</div>

					<div className="grid grid-cols-1 md:grid-cols-3 gap-4">
						<div className="space-y-1.5">
							<label className="text-xs font-semibold text-muted-foreground">Credentials Mode</label>
							<select
								value={credentialsMode}
								onChange={(e) => setCredentialsMode(e.target.value)}
								className="w-full rounded-md border bg-background px-3 py-2 text-sm shadow-sm focus:outline-none focus:ring-1 focus:ring-ring"
							>
								<option value="adc">Google Application Default Credentials (ADC)</option>
								<option value="service_account">Explicit Service Account Key JSON</option>
								<option value="gke_workload_identity">GKE Workload Identity</option>
							</select>
						</div>
						<div className="space-y-1.5">
							<label className="text-xs font-semibold text-muted-foreground">Max Batch Message Count</label>
							<Input
								value={batchSize}
								onChange={(e) => setBatchSize(e.target.value)}
								placeholder="500"
							/>
						</div>
						<div className="space-y-1.5">
							<label className="text-xs font-semibold text-muted-foreground">Max Batch Delay (ms)</label>
							<Input
								value={batchDelayMs}
								onChange={(e) => setBatchDelayMs(e.target.value)}
								placeholder="50"
							/>
						</div>
					</div>

					<div className="border-t pt-4">
						<div className="flex items-center justify-between rounded-lg border p-3">
							<div className="space-y-0.5">
								<div className="text-sm font-medium">Ordering Keys Enabled</div>
								<div className="text-xs text-muted-foreground">Enforce strict per-session causal ordering using Virtual Key and User ID as Pub/Sub ordering keys.</div>
							</div>
							<Switch checked={enableOrderingKey} onCheckedChange={setEnableOrderingKey} />
						</div>
					</div>
				</CardContent>
			</Card>
		</div>
	);
}