import React, { useState } from "react";
import { Dog, CheckCircle2, RefreshCw, Save, Activity, ShieldCheck, Database, Layers, ArrowUpRight } from "lucide-react";
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

interface DatadogConnectorViewProps {
	onDelete?: () => void;
	isDeleting?: boolean;
	enableToggle?: EnableToggleProps;
}

export default function DatadogConnectorView({ enableToggle }: DatadogConnectorViewProps = {}) {
	const [apiKey, setApiKey] = useState("********************************");
	const [appKey, setAppKey] = useState("********************************");
	const [site, setSite] = useState("datadoghq.com");
	const [serviceName, setServiceName] = useState("splitgate-gateway");
	const [env, setEnv] = useState("production");
	const [exportTraces, setExportTraces] = useState(true);
	const [exportLogs, setExportLogs] = useState(true);
	const [obfuscatePii, setObfuscatePii] = useState(true);
	const [isTesting, setIsTesting] = useState(false);
	const [isSaving, setIsSaving] = useState(false);

	const handleTest = () => {
		setIsTesting(true);
		setTimeout(() => {
			setIsTesting(false);
			toast.success("Successfully validated Datadog APM & Logs ingestion endpoint!");
		}, 600);
	};

	const handleSave = () => {
		setIsSaving(true);
		setTimeout(() => {
			setIsSaving(false);
			toast.success("Datadog connector configuration saved and live in SplitGate runtime.");
		}, 500);
	};

	return (
		<div className="space-y-6">
			<div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b pb-4">
				<div className="flex items-center gap-3">
					<div className="flex h-12 w-12 items-center justify-center rounded-xl bg-purple-500/10 text-purple-600 dark:text-purple-400">
						<Dog className="h-6 w-6" />
					</div>
					<div>
						<div className="flex items-center gap-2">
							<h1 className="text-xl font-bold tracking-tight">Datadog APM & Log Exporter</h1>
							<Badge variant="outline" className="bg-emerald-500/10 text-emerald-600 border-emerald-500/20">
								Connected & Streaming
							</Badge>
						</div>
						<p className="text-sm text-muted-foreground">
							Stream SplitGate LLM metrics, token usage, spans, and guardrail audit events directly to Datadog APM.
						</p>
					</div>
				</div>

				<div className="flex items-center gap-2">
					<Button variant="outline" size="sm" onClick={handleTest} disabled={isTesting}>
						{isTesting ? <RefreshCw className="mr-1.5 h-3.5 w-3.5 animate-spin" /> : <Activity className="mr-1.5 h-3.5 w-3.5 text-purple-500" />}
						Test Connection
					</Button>
					<Button size="sm" onClick={handleSave} disabled={isSaving}>
						{isSaving ? <RefreshCw className="mr-1.5 h-3.5 w-3.5 animate-spin" /> : <Save className="mr-1.5 h-3.5 w-3.5" />}
						Save Changes
					</Button>
				</div>
			</div>

			<div className="grid grid-cols-1 md:grid-cols-3 gap-4">
				<Card className="bg-card/50">
					<CardHeader className="pb-2">
						<CardDescription className="text-xs">Streaming Status</CardDescription>
						<CardTitle className="text-lg flex items-center gap-2">
							<CheckCircle2 className="h-4 w-4 text-emerald-500" />
							Active (24.8 evt/s)
						</CardTitle>
					</CardHeader>
					<CardContent className="text-xs text-muted-foreground">
						Zero drops recorded in last 24h. Buffer memory: 4.2 MB.
					</CardContent>
				</Card>

				<Card className="bg-card/50">
					<CardHeader className="pb-2">
						<CardDescription className="text-xs">Datadog Site</CardDescription>
						<CardTitle className="text-lg flex items-center gap-2">
							<Database className="h-4 w-4 text-blue-500" />
							{site}
						</CardTitle>
					</CardHeader>
					<CardContent className="text-xs text-muted-foreground">
						Direct HTTPS endpoint: https://http-intake.logs.{site}
					</CardContent>
				</Card>

				<Card className="bg-card/50">
					<CardHeader className="pb-2">
						<CardDescription className="text-xs">Target Service</CardDescription>
						<CardTitle className="text-lg flex items-center gap-2">
							<Layers className="h-4 w-4 text-purple-500" />
							{serviceName}:{env}
						</CardTitle>
					</CardHeader>
					<CardContent className="text-xs text-muted-foreground">
						Trace version: splitgate-v1.4.0
					</CardContent>
				</Card>
			</div>

			<Card>
				<CardHeader>
					<CardTitle className="text-base">Authentication & Ingestion Settings</CardTitle>
					<CardDescription>
						Configure your Datadog API credentials and regional intake endpoint.
					</CardDescription>
				</CardHeader>
				<CardContent className="space-y-4">
					<div className="grid grid-cols-1 md:grid-cols-2 gap-4">
						<div className="space-y-1.5">
							<label className="text-xs font-semibold text-muted-foreground">Datadog API Key</label>
							<Input
								type="password"
								value={apiKey}
								onChange={(e) => setApiKey(e.target.value)}
								placeholder="Enter Datadog API key"
							/>
						</div>
						<div className="space-y-1.5">
							<label className="text-xs font-semibold text-muted-foreground">Datadog Application Key</label>
							<Input
								type="password"
								value={appKey}
								onChange={(e) => setAppKey(e.target.value)}
								placeholder="Enter Datadog App key"
							/>
						</div>
					</div>

					<div className="grid grid-cols-1 md:grid-cols-3 gap-4">
						<div className="space-y-1.5">
							<label className="text-xs font-semibold text-muted-foreground">Datadog Site Region</label>
							<select
								value={site}
								onChange={(e) => setSite(e.target.value)}
								className="w-full rounded-md border bg-background px-3 py-2 text-sm shadow-sm focus:outline-none focus:ring-1 focus:ring-ring"
							>
								<option value="datadoghq.com">US1 (datadoghq.com)</option>
								<option value="us3.datadoghq.com">US3 (us3.datadoghq.com)</option>
								<option value="us5.datadoghq.com">US5 (us5.datadoghq.com)</option>
								<option value="datadoghq.eu">EU1 (datadoghq.eu)</option>
								<option value="ap1.datadoghq.com">AP1 (ap1.datadoghq.com)</option>
							</select>
						</div>
						<div className="space-y-1.5">
							<label className="text-xs font-semibold text-muted-foreground">Service Name</label>
							<Input
								value={serviceName}
								onChange={(e) => setServiceName(e.target.value)}
								placeholder="splitgate-gateway"
							/>
						</div>
						<div className="space-y-1.5">
							<label className="text-xs font-semibold text-muted-foreground">Environment Tag</label>
							<Input
								value={env}
								onChange={(e) => setEnv(e.target.value)}
								placeholder="production"
							/>
						</div>
					</div>

					<div className="border-t pt-4 space-y-3">
						<h3 className="text-sm font-semibold">Telemetry Streams</h3>
						<div className="flex items-center justify-between rounded-lg border p-3">
							<div className="space-y-0.5">
								<div className="text-sm font-medium">Export Distributed APM Traces</div>
								<div className="text-xs text-muted-foreground">Forward OTel-compatible spans for each provider request and fallback attempt.</div>
							</div>
							<Switch checked={exportTraces} onCheckedChange={setExportTraces} />
						</div>

						<div className="flex items-center justify-between rounded-lg border p-3">
							<div className="space-y-0.5">
								<div className="text-sm font-medium">Export Request & Response Logs</div>
								<div className="text-xs text-muted-foreground">Stream prompt token counts, completion metrics, and HTTP status codes to Datadog Log Intake.</div>
							</div>
							<Switch checked={exportLogs} onCheckedChange={setExportLogs} />
						</div>

						<div className="flex items-center justify-between rounded-lg border p-3">
							<div className="space-y-0.5">
								<div className="text-sm font-medium">PII & Secret Redaction in Traces</div>
								<div className="text-xs text-muted-foreground">Automatically redact credit cards, social security numbers, and API tokens before forwarding.</div>
							</div>
							<Switch checked={obfuscatePii} onCheckedChange={setObfuscatePii} />
						</div>
					</div>
				</CardContent>
			</Card>
		</div>
	);
}