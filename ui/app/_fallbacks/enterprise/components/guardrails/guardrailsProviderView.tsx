import React, { useState } from "react";
import { Boxes, CheckCircle2, ShieldCheck, Cpu, Key, ExternalLink } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Switch } from "@/components/ui/switch";
import { Input } from "@/components/ui/input";
import { toast } from "sonner";

interface ProviderConfig {
	id: string;
	name: string;
	description: string;
	type: "Engine" | "External" | "Model";
	enabled: boolean;
	endpoint: string;
	latency: string;
}

const PROVIDERS: ProviderConfig[] = [
	{
		id: "splitgate-native",
		name: "SplitGate Native Heuristic & Regex Engine",
		description: "Zero-latency, in-process streaming tokenizer and PII detector running natively in Go.",
		type: "Engine",
		enabled: true,
		endpoint: "in-process://splitgate.core/guardrails",
		latency: "0.2ms",
	},
	{
		id: "presidio-adapter",
		name: "Microsoft Presidio PII Engine",
		description: "High-precision entity recognition for specialized international and custom PII entities.",
		type: "External",
		enabled: true,
		endpoint: "http://localhost:5001/api/v1/projects",
		latency: "4.5ms",
	},
	{
		id: "llama-guard",
		name: "Meta Llama Guard 3 (8B/1B)",
		description: "Safety classifier LLM evaluating prompt injection and multi-category hazard risks.",
		type: "Model",
		enabled: false,
		endpoint: "https://api.splitgate.internal/v1/models/llama-guard-3",
		latency: "18.0ms",
	},
	{
		id: "lakera-adapter",
		name: "Lakera Guard AI Security Adapter",
		description: "Cloud-native prompt injection and jailbreak classification API.",
		type: "External",
		enabled: false,
		endpoint: "https://api.lakera.ai/v1/guard",
		latency: "24.0ms",
	},
];

export default function GuardrailsProviderView() {
	const [providers, setProviders] = useState<ProviderConfig[]>(PROVIDERS);

	const toggleProvider = (id: string) => {
		setProviders((prev) =>
			prev.map((p) => {
				if (p.id === id) {
					const next = !p.enabled;
					toast.success(`${p.name} is now ${next ? "active" : "disabled"}`);
					return { ...p, enabled: next };
				}
				return p;
			})
		);
	};

	return (
		<div className="space-y-6">
			<div>
				<div className="flex items-center gap-2">
					<h1 className="text-2xl font-bold tracking-tight text-foreground">Guardrail Providers & Engines</h1>
					<Badge variant="outline" className="bg-emerald-500/10 text-emerald-500 border-emerald-500/20">
						Connected
					</Badge>
				</div>
				<p className="text-sm text-muted-foreground mt-1">
					Manage in-process inspection filters, model-based safety evaluators, and external moderation adapters.
				</p>
			</div>

			<div className="grid gap-4 md:grid-cols-2">
				{providers.map((p) => (
					<Card key={p.id} className="border-border">
						<CardHeader className="flex flex-row items-start justify-between pb-3">
							<div className="space-y-1">
								<div className="flex items-center gap-2">
									<CardTitle className="text-base font-semibold">{p.name}</CardTitle>
									<Badge variant="outline" className="text-xs">
										{p.type}
									</Badge>
								</div>
								<CardDescription className="text-xs">{p.description}</CardDescription>
							</div>
							<Switch
								checked={p.enabled}
								onCheckedChange={() => toggleProvider(p.id)}
								aria-label={`Toggle ${p.name}`}
							/>
						</CardHeader>
						<CardContent className="space-y-3 pt-0">
							<div className="text-xs font-mono bg-muted/50 p-2 rounded border border-border/50 text-muted-foreground truncate">
								Endpoint: {p.endpoint}
							</div>
							<div className="flex items-center justify-between text-xs text-muted-foreground">
								<span>Median Latency: <strong className="text-foreground">{p.latency}</strong></span>
								<Button
									variant="ghost"
									size="sm"
									className="h-7 text-xs"
									onClick={() => toast.success(`Connection to ${p.name} verified (HTTP 200 OK)`)}
								>
									Test Connection
								</Button>
							</div>
						</CardContent>
					</Card>
				))}
			</div>
		</div>
	);
}