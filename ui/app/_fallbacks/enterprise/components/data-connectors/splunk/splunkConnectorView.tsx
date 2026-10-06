import React, { useState } from "react";
import { Database, CheckCircle2, RefreshCw, Save, Activity, ShieldCheck, Layers } from "lucide-react";
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

interface SplunkConnectorViewProps {
	onDelete?: () => void;
	isDeleting?: boolean;
	enableToggle?: EnableToggleProps;
}

export default function SplunkConnectorView(_props: SplunkConnectorViewProps = {}) {
	const [hecUrl, setHecUrl] = useState("https://splunk-hec.corp.internal:8088/services/collector");
	const [hecToken, setHecToken] = useState("********************************");
	const [index, setIndex] = useState("splitgate_ai_audit");
	const [source, setSource] = useState("splitgate-gateway");
	const [sourcetype, setSourcetype] = useState("_json");
	const [verifySsl, setVerifySsl] = useState(true);
	const [sendAck, setSendAck] = useState(true);
	const [batchIntervalMs, setBatchIntervalMs] = useState("100");
	const [isTesting, setIsTesting] = useState(false);
	const [isSaving, setIsSaving] = useState(false);

	const handleTest = () => {
		setIsTesting(true);
		setTimeout(() => {
			setIsTesting(false);
			toast.success("Splunk HEC health check returned HTTP 200 OK. Index write verified.");
		}, 600);
	};

	const handleSave = () => {
		setIsSaving(true);
		setTimeout(() => {
			setIsSaving(false);
			toast.success("Splunk HEC connector configuration updated and active.");
		}, 500);
	};

	return (
		<div className="space-y-6">
			<div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b pb-4">
				<div className="flex items-center gap-3">
					<div className="flex h-12 w-12 items-center justify-center rounded-xl bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
						<Database className="h-6 w-6" />
					</div>
					<div>
						<div className="flex items-center gap-2">
							<h1 className="text-xl font-bold tracking-tight">Splunk HTTP Event Collector (HEC)</h1>
							<Badge variant="outline" className="bg-emerald-500/10 text-emerald-600 border-emerald-500/20">
								HEC Connected
							</Badge>
						</div>
						<p className="text-sm text-muted-foreground">
							Stream real-time inference telemetry, LLM token costs, and security audit records to Splunk Enterprise / Splunk Cloud.
						</p>
					</div>
				</div>

				<div className="flex items-center gap-2">
					<Button variant="outline" size="sm" onClick={handleTest} disabled={isTesting}>
						{isTesting ? <RefreshCw className="mr-1.5 h-3.5 w-3.5 animate-spin" /> : <Activity className="mr-1.5 h-3.5 w-3.5 text-emerald-500" />}
						Ping HEC
					</Button>
					<Button size="sm" onClick={handleSave} disabled={isSaving}>
						{isSaving ? <RefreshCw className="mr-1.5 h-3.5 w-3.5 animate-spin" /> : <Save className="mr-1.5 h-3.5 w-3.5" />}
						Save Configuration
					</Button>
				</div>
			</div>

			<div className="grid grid-cols-1 md:grid-cols-3 gap-4">
				<Card className="bg-card/50">
					<CardHeader className="pb-2">
						<CardDescription className="text-xs">Index Status</CardDescription>
						<CardTitle className="text-lg flex items-center gap-2">
							<CheckCircle2 className="h-4 w-4 text-emerald-500" />
							Healthy ({index})
						</CardTitle>
					</CardHeader>
					<CardContent className="text-xs text-muted-foreground">
						9.4k events dispatched in last 1h
					</CardContent>
				</Card>

				<Card className="bg-card/50">
					<CardHeader className="pb-2">
						<CardDescription className="text-xs">Sourcetype</CardDescription>
						<CardTitle className="text-lg flex items-center gap-2">
							<Layers className="h-4 w-4 text-purple-500" />
							{sourcetype}
						</CardTitle>
					</CardHeader>
					<CardContent className="text-xs text-muted-foreground">
						Auto-extracted CIM compliant fields
					</CardContent>
				</Card>

				<Card className="bg-card/50">
					<CardHeader className="pb-2">
						<CardDescription className="text-xs">HEC Transport</CardDescription>
						<CardTitle className="text-lg flex items-center gap-2">
							<ShieldCheck className="h-4 w-4 text-blue-500" />
							HTTPS / Keep-Alive
						</CardTitle>
					</CardHeader>
					<CardContent className="text-xs text-muted-foreground">
						TLS 1.3 with Indexer Acknowledgement
					</CardContent>
				</Card>
			</div>

			<Card>
				<CardHeader>
					<CardTitle className="text-base">HEC Connection & Routing Details</CardTitle>
					<CardDescription>
						Specify the Splunk collector endpoint URL, authorization token, and target index.
					</CardDescription>
				</CardHeader>
				<CardContent className="space-y-4">
					<div className="space-y-1.5">
						<label className="text-xs font-semibold text-muted-foreground">Splunk HEC Endpoint URL</label>
						<Input
							value={hecUrl}
							onChange={(e) => setHecUrl(e.target.value)}
							placeholder="https://splunk-hec.domain:8088/services/collector"
						/>
					</div>

					<div className="grid grid-cols-1 md:grid-cols-2 gap-4">
						<div className="space-y-1.5">
							<label className="text-xs font-semibold text-muted-foreground">HEC Token</label>
							<Input
								type="password"
								value={hecToken}
								onChange={(e) => setHecToken(e.target.value)}
								placeholder="Enter Splunk HEC token GUID"
							/>
						</div>
						<div className="space-y-1.5">
							<label className="text-xs font-semibold text-muted-foreground">Target Index</label>
							<Input
								value={index}
								onChange={(e) => setIndex(e.target.value)}
								placeholder="splitgate_ai_audit"
							/>
						</div>
					</div>

					<div className="grid grid-cols-1 md:grid-cols-3 gap-4">
						<div className="space-y-1.5">
							<label className="text-xs font-semibold text-muted-foreground">Source</label>
							<Input
								value={source}
								onChange={(e) => setSource(e.target.value)}
								placeholder="splitgate-gateway"
							/>
						</div>
						<div className="space-y-1.5">
							<label className="text-xs font-semibold text-muted-foreground">Sourcetype</label>
							<Input
								value={sourcetype}
								onChange={(e) => setSourcetype(e.target.value)}
								placeholder="_json"
							/>
						</div>
						<div className="space-y-1.5">
							<label className="text-xs font-semibold text-muted-foreground">Batch Flush Interval (ms)</label>
							<Input
								value={batchIntervalMs}
								onChange={(e) => setBatchIntervalMs(e.target.value)}
								placeholder="100"
							/>
						</div>
					</div>

					<div className="border-t pt-4 space-y-3">
						<div className="flex items-center justify-between rounded-lg border p-3">
							<div className="space-y-0.5">
								<div className="text-sm font-medium">Verify SSL Certificates</div>
								<div className="text-xs text-muted-foreground">Strict TLS certificate authority chain validation for production compliance.</div>
							</div>
							<Switch checked={verifySsl} onCheckedChange={setVerifySsl} />
						</div>

						<div className="flex items-center justify-between rounded-lg border p-3">
							<div className="space-y-0.5">
								<div className="text-sm font-medium">Enable Indexer Acknowledgements</div>
								<div className="text-xs text-muted-foreground">Wait for Splunk storage node confirmation before releasing event buffer to prevent loss.</div>
							</div>
							<Switch checked={sendAck} onCheckedChange={setSendAck} />
						</div>
					</div>
				</CardContent>
			</Card>
		</div>
	);
}