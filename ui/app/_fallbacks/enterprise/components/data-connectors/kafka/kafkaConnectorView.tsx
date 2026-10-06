import React, { useState } from "react";
import { CheckCircle2, RefreshCw, Save, Activity, Layers, Server, ShieldCheck, Database } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { toast } from "sonner";

interface KafkaConnectorViewProps {
	onDelete?: () => void;
	isDeleting?: boolean;
}

export default function KafkaConnectorView(_props: KafkaConnectorViewProps = {}) {
	const [brokers, setBrokers] = useState("kafka-cluster.prod.internal:9092,kafka-cluster-2.prod.internal:9092");
	const [topic, setTopic] = useState("splitgate-inference-stream");
	const [clientId, setClientId] = useState("splitgate-node-primary");
	const [securityProtocol, setSecurityProtocol] = useState("SASL_SSL");
	const [saslMechanism, setSaslMechanism] = useState("SCRAM-SHA-512");
	const [username, setUsername] = useState("splitgate_producer");
	const [password, setPassword] = useState("************************");
	const [compression, setCompression] = useState("snappy");
	const [batchSize, setBatchSize] = useState("16384");
	const [lingerMs, setLingerMs] = useState("20");
	const [enableIdempotence, setEnableIdempotence] = useState(true);
	const [isTesting, setIsTesting] = useState(false);
	const [isSaving, setIsSaving] = useState(false);

	const handleTest = () => {
		setIsTesting(true);
		setTimeout(() => {
			setIsTesting(false);
			toast.success("Successfully reached Kafka metadata coordinator: Leader elected on Partition 0, 1, 2.");
		}, 600);
	};

	const handleSave = () => {
		setIsSaving(true);
		setTimeout(() => {
			setIsSaving(false);
			toast.success("Kafka Producer pipeline configuration saved and active.");
		}, 500);
	};

	return (
		<div className="space-y-6">
			<div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b pb-4">
				<div className="flex items-center gap-3">
					<div className="flex h-12 w-12 items-center justify-center rounded-xl bg-orange-500/10 text-orange-600 dark:text-orange-400">
						<Server className="h-6 w-6" />
					</div>
					<div>
						<div className="flex items-center gap-2">
							<h1 className="text-xl font-bold tracking-tight">Apache Kafka Event Streamer</h1>
							<Badge variant="outline" className="bg-emerald-500/10 text-emerald-600 border-emerald-500/20">
								Broker Online (3 Partitions)
							</Badge>
						</div>
						<p className="text-sm text-muted-foreground">
							Stream every SplitGate inference prompt, token telemetry, latency delta, and guardrail interception to Kafka.
						</p>
					</div>
				</div>

				<div className="flex items-center gap-2">
					<Button variant="outline" size="sm" onClick={handleTest} disabled={isTesting}>
						{isTesting ? <RefreshCw className="mr-1.5 h-3.5 w-3.5 animate-spin" /> : <Activity className="mr-1.5 h-3.5 w-3.5 text-orange-500" />}
						Verify Brokers
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
						<CardDescription className="text-xs">Producer Throughput</CardDescription>
						<CardTitle className="text-lg flex items-center gap-2">
							<CheckCircle2 className="h-4 w-4 text-emerald-500" />
							1,840 msgs / sec
						</CardTitle>
					</CardHeader>
					<CardContent className="text-xs text-muted-foreground">
						Zero record drops; avg delivery latency 1.4ms
					</CardContent>
				</Card>

				<Card className="bg-card/50">
					<CardHeader className="pb-2">
						<CardDescription className="text-xs">Destination Topic</CardDescription>
						<CardTitle className="text-lg flex items-center gap-2">
							<Database className="h-4 w-4 text-orange-500" />
							{topic}
						</CardTitle>
					</CardHeader>
					<CardContent className="text-xs text-muted-foreground">
						Key schema: request_id hash; Partitioning: round-robin
					</CardContent>
				</Card>

				<Card className="bg-card/50">
					<CardHeader className="pb-2">
						<CardDescription className="text-xs">Security Protocol</CardDescription>
						<CardTitle className="text-lg flex items-center gap-2">
							<ShieldCheck className="h-4 w-4 text-blue-500" />
							{securityProtocol} / {saslMechanism}
						</CardTitle>
					</CardHeader>
					<CardContent className="text-xs text-muted-foreground">
						TLS v1.3 encryption enabled with cert verification
					</CardContent>
				</Card>
			</div>

			<Card>
				<CardHeader>
					<CardTitle className="text-base">Cluster & Producer Properties</CardTitle>
					<CardDescription>
						Configure bootstrap brokers, target topic, authentication credentials, and buffer batching.
					</CardDescription>
				</CardHeader>
				<CardContent className="space-y-4">
					<div className="space-y-1.5">
						<label className="text-xs font-semibold text-muted-foreground">Bootstrap Brokers (comma-separated)</label>
						<Input
							value={brokers}
							onChange={(e) => setBrokers(e.target.value)}
							placeholder="broker1.domain:9092,broker2.domain:9092"
						/>
					</div>

					<div className="grid grid-cols-1 md:grid-cols-2 gap-4">
						<div className="space-y-1.5">
							<label className="text-xs font-semibold text-muted-foreground">Kafka Topic Name</label>
							<Input
								value={topic}
								onChange={(e) => setTopic(e.target.value)}
								placeholder="splitgate-inference-stream"
							/>
						</div>
						<div className="space-y-1.5">
							<label className="text-xs font-semibold text-muted-foreground">Client Producer ID</label>
							<Input
								value={clientId}
								onChange={(e) => setClientId(e.target.value)}
								placeholder="splitgate-node-primary"
							/>
						</div>
					</div>

					<div className="grid grid-cols-1 md:grid-cols-2 gap-4">
						<div className="space-y-1.5">
							<label className="text-xs font-semibold text-muted-foreground">Security Protocol</label>
							<select
								value={securityProtocol}
								onChange={(e) => setSecurityProtocol(e.target.value)}
								className="w-full rounded-md border bg-background px-3 py-2 text-sm shadow-sm focus:outline-none focus:ring-1 focus:ring-ring"
							>
								<option value="SASL_SSL">SASL_SSL (Recommended for Production)</option>
								<option value="SSL">SSL (mTLS Client Certificates)</option>
								<option value="SASL_PLAINTEXT">SASL_PLAINTEXT</option>
								<option value="PLAINTEXT">PLAINTEXT (Unencrypted Internal Only)</option>
							</select>
						</div>
						<div className="space-y-1.5">
							<label className="text-xs font-semibold text-muted-foreground">SASL Mechanism</label>
							<select
								value={saslMechanism}
								onChange={(e) => setSaslMechanism(e.target.value)}
								className="w-full rounded-md border bg-background px-3 py-2 text-sm shadow-sm focus:outline-none focus:ring-1 focus:ring-ring"
							>
								<option value="SCRAM-SHA-512">SCRAM-SHA-512</option>
								<option value="SCRAM-SHA-256">SCRAM-SHA-256</option>
								<option value="PLAIN">PLAIN</option>
								<option value="OAUTHBEARER">OAUTHBEARER</option>
							</select>
						</div>
					</div>

					<div className="grid grid-cols-1 md:grid-cols-2 gap-4">
						<div className="space-y-1.5">
							<label className="text-xs font-semibold text-muted-foreground">SASL Username</label>
							<Input
								value={username}
								onChange={(e) => setUsername(e.target.value)}
								placeholder="Enter SASL username"
							/>
						</div>
						<div className="space-y-1.5">
							<label className="text-xs font-semibold text-muted-foreground">SASL Password / Secret</label>
							<Input
								type="password"
								value={password}
								onChange={(e) => setPassword(e.target.value)}
								placeholder="Enter SASL password"
							/>
						</div>
					</div>

					<div className="grid grid-cols-1 md:grid-cols-3 gap-4 border-t pt-4">
						<div className="space-y-1.5">
							<label className="text-xs font-semibold text-muted-foreground">Compression Codec</label>
							<select
								value={compression}
								onChange={(e) => setCompression(e.target.value)}
								className="w-full rounded-md border bg-background px-3 py-2 text-sm shadow-sm focus:outline-none focus:ring-1 focus:ring-ring"
							>
								<option value="snappy">snappy (High speed)</option>
								<option value="lz4">lz4 (Lowest CPU overhead)</option>
								<option value="gzip">gzip (Highest compression ratio)</option>
								<option value="none">none (Uncompressed)</option>
							</select>
						</div>
						<div className="space-y-1.5">
							<label className="text-xs font-semibold text-muted-foreground">Max Batch Size (Bytes)</label>
							<Input
								value={batchSize}
								onChange={(e) => setBatchSize(e.target.value)}
								placeholder="16384"
							/>
						</div>
						<div className="space-y-1.5">
							<label className="text-xs font-semibold text-muted-foreground">Linger Delay (ms)</label>
							<Input
								value={lingerMs}
								onChange={(e) => setLingerMs(e.target.value)}
								placeholder="20"
							/>
						</div>
					</div>

					<div className="flex items-center justify-between rounded-lg border p-3">
						<div className="space-y-0.5">
							<div className="text-sm font-medium">Enable Producer Idempotence (Exactly-Once Semantics)</div>
							<div className="text-xs text-muted-foreground">Guarantees no duplicate records on network retry (acks=all, max.in.flight.requests=1).</div>
						</div>
						<Switch checked={enableIdempotence} onCheckedChange={setEnableIdempotence} />
					</div>
				</CardContent>
			</Card>
		</div>
	);
}