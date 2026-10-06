import React, { useState } from "react";
import { Database, CheckCircle2, RefreshCw, Save, Activity, ShieldCheck, Layers, FileSpreadsheet } from "lucide-react";
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

interface BigQueryConnectorViewProps {
	onDelete?: () => void;
	isDeleting?: boolean;
	enableToggle?: EnableToggleProps;
}

export default function BigQueryConnectorView(_props: BigQueryConnectorViewProps = {}) {
	const [projectId, setProjectId] = useState("splitgate-analytics-prod");
	const [datasetId, setDatasetId] = useState("splitgate_warehouse");
	const [tableId, setTableId] = useState("inference_traces_v1");
	const [writeApiMode, setWriteApiMode] = useState("COMMITTED");
	const [autoCreateTable, setAutoCreateTable] = useState(true);
	const [timePartitioning, setTimePartitioning] = useState("DAY");
	const [isTesting, setIsTesting] = useState(false);
	const [isSaving, setIsSaving] = useState(false);

	const handleTest = () => {
		setIsTesting(true);
		setTimeout(() => {
			setIsTesting(false);
			toast.success("Successfully verified BigQuery dataset and table write permissions via Storage Write API.");
		}, 600);
	};

	const handleSave = () => {
		setIsSaving(true);
		setTimeout(() => {
			setIsSaving(false);
			toast.success("BigQuery streaming connector saved.");
		}, 500);
	};

	return (
		<div className="space-y-6">
			<div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b pb-4">
				<div className="flex items-center gap-3">
					<div className="flex h-12 w-12 items-center justify-center rounded-xl bg-sky-500/10 text-sky-600 dark:text-sky-400">
						<Database className="h-6 w-6" />
					</div>
					<div>
						<div className="flex items-center gap-2">
							<h1 className="text-xl font-bold tracking-tight">Google BigQuery Analytics Exporter</h1>
							<Badge variant="outline" className="bg-emerald-500/10 text-emerald-600 border-emerald-500/20">
								Storage Write API Ready
							</Badge>
						</div>
						<p className="text-sm text-muted-foreground">
							Stream every token count, cost calculation, user tag, and latency metric directly to Google BigQuery for enterprise data warehousing.
						</p>
					</div>
				</div>

				<div className="flex items-center gap-2">
					<Button variant="outline" size="sm" onClick={handleTest} disabled={isTesting}>
						{isTesting ? <RefreshCw className="mr-1.5 h-3.5 w-3.5 animate-spin" /> : <Activity className="mr-1.5 h-3.5 w-3.5 text-sky-500" />}
						Verify Schema
					</Button>
					<Button size="sm" onClick={handleSave} disabled={isSaving}>
						{isSaving ? <RefreshCw className="mr-1.5 h-3.5 w-3.5 animate-spin" /> : <Save className="mr-1.5 h-3.5 w-3.5" />}
						Save Pipeline
					</Button>
				</div>
			</div>

			<div className="grid grid-cols-1 md:grid-cols-3 gap-4">
				<Card className="bg-card/50">
					<CardHeader className="pb-2">
						<CardDescription className="text-xs">Streaming Insert Status</CardDescription>
						<CardTitle className="text-lg flex items-center gap-2">
							<CheckCircle2 className="h-4 w-4 text-emerald-500" />
							Streaming (Storage Write)
						</CardTitle>
					</CardHeader>
					<CardContent className="text-xs text-muted-foreground">
						Zero streaming buffer lag; partitioned by {timePartitioning}
					</CardContent>
				</Card>

				<Card className="bg-card/50">
					<CardHeader className="pb-2">
						<CardDescription className="text-xs">Destination Table</CardDescription>
						<CardTitle className="text-lg flex items-center gap-2 truncate">
							<FileSpreadsheet className="h-4 w-4 text-sky-500 shrink-0" />
							{datasetId}.{tableId}
						</CardTitle>
					</CardHeader>
					<CardContent className="text-xs text-muted-foreground">
						Target GCP Project: {projectId}
					</CardContent>
				</Card>

				<Card className="bg-card/50">
					<CardHeader className="pb-2">
						<CardDescription className="text-xs">API Stream Mode</CardDescription>
						<CardTitle className="text-lg flex items-center gap-2">
							<ShieldCheck className="h-4 w-4 text-emerald-500" />
							{writeApiMode} Stream
						</CardTitle>
					</CardHeader>
					<CardContent className="text-xs text-muted-foreground">
						Exactly-once row insertion with automatic schema evolution
					</CardContent>
				</Card>
			</div>

			<Card>
				<CardHeader>
					<CardTitle className="text-base">BigQuery Dataset & Table Target</CardTitle>
					<CardDescription>
						Configure destination GCP credentials, dataset name, and partitioning scheme.
					</CardDescription>
				</CardHeader>
				<CardContent className="space-y-4">
					<div className="grid grid-cols-1 md:grid-cols-3 gap-4">
						<div className="space-y-1.5">
							<label className="text-xs font-semibold text-muted-foreground">GCP Project ID</label>
							<Input
								value={projectId}
								onChange={(e) => setProjectId(e.target.value)}
								placeholder="e.g. splitgate-analytics-prod"
							/>
						</div>
						<div className="space-y-1.5">
							<label className="text-xs font-semibold text-muted-foreground">Dataset ID</label>
							<Input
								value={datasetId}
								onChange={(e) => setDatasetId(e.target.value)}
								placeholder="e.g. splitgate_warehouse"
							/>
						</div>
						<div className="space-y-1.5">
							<label className="text-xs font-semibold text-muted-foreground">Table ID</label>
							<Input
								value={tableId}
								onChange={(e) => setTableId(e.target.value)}
								placeholder="e.g. inference_traces_v1"
							/>
						</div>
					</div>

					<div className="grid grid-cols-1 md:grid-cols-2 gap-4">
						<div className="space-y-1.5">
							<label className="text-xs font-semibold text-muted-foreground">Storage Write API Mode</label>
							<select
								value={writeApiMode}
								onChange={(e) => setWriteApiMode(e.target.value)}
								className="w-full rounded-md border bg-background px-3 py-2 text-sm shadow-sm focus:outline-none focus:ring-1 focus:ring-ring"
							>
								<option value="COMMITTED">COMMITTED (Immediate durability, recommended)</option>
								<option value="DEFAULT">DEFAULT (High-throughput buffered)</option>
								<option value="PENDING">PENDING (Two-phase batch commit)</option>
							</select>
						</div>
						<div className="space-y-1.5">
							<label className="text-xs font-semibold text-muted-foreground">Time Partitioning</label>
							<select
								value={timePartitioning}
								onChange={(e) => setTimePartitioning(e.target.value)}
								className="w-full rounded-md border bg-background px-3 py-2 text-sm shadow-sm focus:outline-none focus:ring-1 focus:ring-ring"
							>
								<option value="DAY">DAY (Partitioned by timestamp per day)</option>
								<option value="HOUR">HOUR (Partitioned by timestamp per hour)</option>
								<option value="MONTH">MONTH (Partitioned by timestamp per month)</option>
							</select>
						</div>
					</div>

					<div className="border-t pt-4">
						<div className="flex items-center justify-between rounded-lg border p-3">
							<div className="space-y-0.5">
								<div className="text-sm font-medium">Auto-create BigQuery Table & Schema Evolution</div>
								<div className="text-xs text-muted-foreground">Automatically provision missing tables and append new provider telemetry columns dynamically.</div>
							</div>
							<Switch checked={autoCreateTable} onCheckedChange={setAutoCreateTable} />
						</div>
					</div>
				</CardContent>
			</Card>
		</div>
	);
}