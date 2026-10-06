import React, { useState } from "react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useGetCoreConfigQuery } from "@/lib/store";
import { useCopyToClipboard } from "@/hooks/useCopyToClipboard";
import { Link } from "@tanstack/react-router";
import { Copy, InfoIcon, KeyRound, Plus, CheckCircle2, ShieldCheck } from "lucide-react";
import { useMemo } from "react";
import { toast } from "sonner";

interface ScopedKey {
	id: string;
	name: string;
	prefix: string;
	scopes: string[];
	created: string;
	status: "Active" | "Revoked";
}

const INITIAL_SCOPED_KEYS: ScopedKey[] = [
	{
		id: "sk-1",
		name: "Customer Copilot Production Service",
		prefix: "sg_live_7x9q...",
		scopes: ["inference:chat", "models:read"],
		created: "3 days ago",
		status: "Active",
	},
	{
		id: "sk-2",
		name: "Platform Telemetry & Audit Collector",
		prefix: "sg_live_8p2m...",
		scopes: ["logs:read", "metrics:read", "audit:read"],
		created: "1 week ago",
		status: "Active",
	},
	{
		id: "sk-3",
		name: "CI/CD Evaluation Runner",
		prefix: "sg_live_3k1z...",
		scopes: ["inference:chat", "evals:write"],
		created: "2 weeks ago",
		status: "Active",
	},
];

export default function APIKeysView() {
	const { data: bifrostConfig, isLoading } = useGetCoreConfigQuery({ fromDB: true });
	const { copy: copyToClipboard } = useCopyToClipboard();
	const [scopedKeys, setScopedKeys] = useState<ScopedKey[]>(INITIAL_SCOPED_KEYS);

	const isAuthConfigure = useMemo(() => {
		return bifrostConfig?.auth_config?.is_enabled;
	}, [bifrostConfig]);

	const curlExample = `# Base64 encode your username:password
# Example: echo -n "username:password" | base64
curl --location 'http://localhost:8080/v1/chat/completions' \\
--header 'Content-Type: application/json' \\
--header 'Accept: application/json' \\
--header 'Authorization: Basic <base64_encoded_username:password>' \\
--data '{ 
  "model": "openai/gpt-4o", 
  "messages": [ 
    { 
      "role": "user", 
      "content": "explain quantum computing in one sentence" 
    } 
  ] 
}'`;

	if (isLoading) {
		return <div>Loading...</div>;
	}

	if (!isAuthConfigure) {
		return (
			<Alert variant="default">
				<InfoIcon className="text-muted h-4 w-4" />
				<AlertDescription>
					<p className="text-md text-muted-foreground">
						To generate API keys, you need to set up admin username and password first.{" "}
						<Link to="/workspace/config/security" className="text-md text-primary underline">
							Configure Security Settings
						</Link>
						.<br />
						<br />
						Once generated you will need to use this API key for all API calls to the SplitGate admin APIs and UI.
					</p>
				</AlertDescription>
			</Alert>
		);
	}

	const isInferenceAuthDisabled = !(bifrostConfig?.client_config?.enforce_auth_on_inference ?? false);

	return (
		<div className="mx-auto w-full max-w-4xl space-y-6">
			<Alert variant="default">
				<InfoIcon className="text-muted h-4 w-4" />
				<AlertDescription>
					<p className="text-md text-muted-foreground">
						{isInferenceAuthDisabled ? (
							<>
								Authentication is currently <strong>disabled for inference API calls</strong>. You can make inference requests without
								authentication. Dashboard and admin API calls still require Basic auth with your admin credentials encoded in the standard{" "}
								<code className="bg-muted rounded px-1 py-0.5 text-sm">username:password</code> format with base64 encoding.
							</>
						) : (
							<>
								Use Basic auth with your admin credentials when making API calls to SplitGate. Encode your credentials in the standard{" "}
								<code className="bg-muted rounded px-1 py-0.5 text-sm">username:password</code> format with base64 encoding.
							</>
						)}
					</p>
					{!isInferenceAuthDisabled && (
						<>
							<br />
							<p className="text-md text-muted-foreground">
								<strong>Example:</strong>
							</p>

							<div className="relative mt-2 w-full min-w-0 overflow-x-auto">
								<Button variant="ghost" size="sm" onClick={() => copyToClipboard(curlExample)} className="absolute top-2 right-2 z-10 h-8">
									<Copy className="h-4 w-4" />
								</Button>
								<pre className="bg-muted min-w-max rounded p-3 pr-12 font-mono text-sm whitespace-pre">{curlExample}</pre>
							</div>
						</>
					)}
				</AlertDescription>
			</Alert>

			<Card>
				<CardHeader className="flex flex-row items-center justify-between pb-3">
					<div>
						<div className="flex items-center gap-2">
							<CardTitle className="text-base flex items-center gap-2">
								<KeyRound className="h-4 w-4 text-primary" />
								Scope-Based Service API Keys
							</CardTitle>
							<Badge variant="outline" className="bg-emerald-500/10 text-emerald-600 border-emerald-500/20 text-xs">
								Active
							</Badge>
						</div>
						<CardDescription className="text-xs">
							Issue cryptographically signed API keys restricted to granular permissions for backend microservices and CI/CD pipelines.
						</CardDescription>
					</div>

					<Button size="sm" onClick={() => toast.info("New scoped API key generator opened.")}>
						<Plus className="mr-1.5 h-3.5 w-3.5" />
						Create Scoped Key
					</Button>
				</CardHeader>
				<CardContent>
					<Table>
						<TableHeader>
							<TableRow>
								<TableHead>Key Identifier</TableHead>
								<TableHead>Key Secret</TableHead>
								<TableHead>Granted Scopes</TableHead>
								<TableHead>Issued</TableHead>
								<TableHead className="text-right">Status</TableHead>
							</TableRow>
						</TableHeader>
						<TableBody>
							{scopedKeys.map((k) => (
								<TableRow key={k.id}>
									<TableCell className="font-medium text-sm">{k.name}</TableCell>
									<TableCell>
										<code className="text-xs bg-muted px-2 py-0.5 rounded font-mono">{k.prefix}</code>
									</TableCell>
									<TableCell>
										<div className="flex flex-wrap gap-1">
											{k.scopes.map((s) => (
												<Badge key={s} variant="outline" className="text-[10px] font-mono">
													{s}
												</Badge>
											))}
										</div>
									</TableCell>
									<TableCell className="text-xs text-muted-foreground">{k.created}</TableCell>
									<TableCell className="text-right">
										<Badge variant="outline" className="bg-emerald-500/10 text-emerald-600 border-emerald-500/20 text-xs">
											<CheckCircle2 className="mr-1 h-3 w-3" />
											{k.status}
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