import React, { useState } from "react";
import { ShieldCheck, Plus, Layers, Key, CheckCircle2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { toast } from "sonner";

interface AccessProfile {
	id: string;
	name: string;
	description: string;
	allowedProviders: string[];
	maxTpmLimit: string;
	maxRpmLimit: string;
	virtualKeysCount: number;
}

const PROFILES: AccessProfile[] = [
	{
		id: "profile-standard",
		name: "General Engineering Standard",
		description: "Standard access profile granting access to Tier-1 reasoning models with standard rate limits.",
		allowedProviders: ["OpenAI", "Anthropic", "Google Gemini"],
		maxTpmLimit: "500,000 TPM",
		maxRpmLimit: "1,200 RPM",
		virtualKeysCount: 14,
	},
	{
		id: "profile-high-throughput",
		name: "Batch & High Throughput Ingestion",
		description: "High concurrency profile designed for background data pipelines and bulk embedding jobs.",
		allowedProviders: ["OpenAI", "Groq", "Bedrock"],
		maxTpmLimit: "2,500,000 TPM",
		maxRpmLimit: "5,000 RPM",
		virtualKeysCount: 6,
	},
	{
		id: "profile-restricted-safety",
		name: "Regulated Healthcare & Finance",
		description: "Restricted profile enforcing strict PII redaction and limiting routing to HIPAA-eligible endpoints.",
		allowedProviders: ["Azure OpenAI", "AWS Bedrock Mantle"],
		maxTpmLimit: "200,000 TPM",
		maxRpmLimit: "600 RPM",
		virtualKeysCount: 4,
	},
];

export default function AccessProfilesIndexView() {
	const [profiles, setProfiles] = useState<AccessProfile[]>(PROFILES);

	return (
		<div className="space-y-6">
			<div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
				<div>
					<div className="flex items-center gap-2">
						<h1 className="text-2xl font-bold tracking-tight text-foreground">Access Profiles</h1>
						<Badge variant="outline" className="bg-emerald-500/10 text-emerald-500 border-emerald-500/20">
							Active
						</Badge>
					</div>
					<p className="text-sm text-muted-foreground mt-0.5">
						Reusable governance profiles binding rate limits, budget policies, and allowed provider pools to virtual keys.
					</p>
				</div>
				<div className="flex items-center gap-2">
					<Button size="sm" onClick={() => toast.success("Access profile wizard opened")}>
						<Plus className="mr-1.5 h-3.5 w-3.5" />
						Create Profile
					</Button>
				</div>
			</div>

			<div className="grid gap-4 md:grid-cols-3">
				{profiles.map((p) => (
					<Card key={p.id} className="border-border">
						<CardHeader className="pb-3">
							<div className="flex items-center justify-between">
								<CardTitle className="text-base font-semibold">{p.name}</CardTitle>
								<Badge variant="outline" className="text-xs">
									{p.virtualKeysCount} keys
								</Badge>
							</div>
							<CardDescription className="text-xs mt-1">{p.description}</CardDescription>
						</CardHeader>
						<CardContent className="space-y-3 pt-0 text-xs">
							<div className="space-y-1">
								<span className="text-muted-foreground">Allowed Upstreams:</span>
								<div className="flex flex-wrap gap-1 mt-1">
									{p.allowedProviders.map((prov) => (
										<Badge key={prov} variant="secondary" className="text-[10px]">
											{prov}
										</Badge>
									))}
								</div>
							</div>
							<div className="flex justify-between pt-2 border-t text-muted-foreground">
								<span>TPM Cap: <strong className="text-foreground">{p.maxTpmLimit}</strong></span>
								<span>RPM Cap: <strong className="text-foreground">{p.maxRpmLimit}</strong></span>
							</div>
						</CardContent>
					</Card>
				))}
			</div>
		</div>
	);
}