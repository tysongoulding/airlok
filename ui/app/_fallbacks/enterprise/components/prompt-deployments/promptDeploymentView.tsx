import React, { useState } from "react";
import { Router, Plus, CheckCircle2, GitBranch, Split, Play, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { toast } from "sonner";

interface PromptDeployment {
	id: string;
	name: string;
	slug: string;
	activeVersion: string;
	canaryVersion?: string;
	canaryWeight?: number;
	model: string;
	status: "Production" | "Canary Testing";
}

const INITIAL_DEPLOYMENTS: PromptDeployment[] = [
	{
		id: "dep-1",
		name: "Customer Support RAG Prompt",
		slug: "support-rag-v2",
		activeVersion: "v2.4.1",
		canaryVersion: "v2.5.0-rc1",
		canaryWeight: 10,
		model: "gpt-4o",
		status: "Canary Testing",
	},
	{
		id: "dep-2",
		name: "Code Review Assistant Prompt",
		slug: "code-review-system",
		activeVersion: "v1.8.0",
		model: "claude-3-5-sonnet",
		status: "Production",
	},
	{
		id: "dep-3",
		name: "Legal Clause Classifier",
		slug: "clause-classifier",
		activeVersion: "v3.1.2",
		model: "llama-3.3-70b",
		status: "Production",
	},
];

export default function PromptDeploymentView(_props?: { omitTitle?: boolean }) {
	const [deployments, setDeployments] = useState<PromptDeployment[]>(INITIAL_DEPLOYMENTS);

	return (
		<div className="space-y-6">
			{!_props?.omitTitle && (
				<div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b pb-4">
					<div className="flex items-center gap-3">
						<div className="flex h-12 w-12 items-center justify-center rounded-xl bg-purple-500/10 text-purple-600 dark:text-purple-400">
							<Router className="h-6 w-6" />
						</div>
						<div>
							<div className="flex items-center gap-2">
								<h1 className="text-xl font-bold tracking-tight">Prompt Deployments & Canary A/B</h1>
								<Badge variant="outline" className="bg-emerald-500/10 text-emerald-600 border-emerald-500/20">
									Active
								</Badge>
							</div>
							<p className="text-sm text-muted-foreground">
								Deploy versioned prompts behind stable endpoint aliases with traffic splitting, canary rollouts, and rollback triggers.
							</p>
						</div>
					</div>

					<Button size="sm" onClick={() => toast.info("Prompt deployment modal opened.")}>
						<Plus className="mr-1.5 h-4 w-4" />
						New Deployment
					</Button>
				</div>
			)}

			<Card>
				<CardHeader className="pb-2">
					<CardTitle className="text-base">Active Deployments</CardTitle>
				</CardHeader>
				<CardContent>
					<Table>
						<TableHeader>
							<TableRow>
								<TableHead>Deployment Alias</TableHead>
								<TableHead>Production Version</TableHead>
								<TableHead>Canary Traffic</TableHead>
								<TableHead>Underlying Model</TableHead>
								<TableHead className="text-right">Rollout Status</TableHead>
							</TableRow>
						</TableHeader>
						<TableBody>
							{deployments.map((dep) => (
								<TableRow key={dep.id}>
									<TableCell>
										<div className="font-semibold text-sm">{dep.name}</div>
										<code className="text-xs text-muted-foreground font-mono">{dep.slug}</code>
									</TableCell>
									<TableCell>
										<Badge variant="outline" className="bg-primary/10 text-primary border-primary/20">
											<GitBranch className="mr-1 h-3 w-3" />
											{dep.activeVersion}
										</Badge>
									</TableCell>
									<TableCell>
										{dep.canaryVersion ? (
											<div className="flex items-center gap-2">
												<Badge variant="outline" className="bg-amber-500/10 text-amber-600 border-amber-500/20">
													<Split className="mr-1 h-3 w-3" />
													{dep.canaryWeight}% to {dep.canaryVersion}
												</Badge>
											</div>
										) : (
											<span className="text-xs text-muted-foreground">100% to primary</span>
										)}
									</TableCell>
									<TableCell className="text-xs font-mono text-muted-foreground">{dep.model}</TableCell>
									<TableCell className="text-right">
										<Badge
											variant="outline"
											className={
												dep.status === "Production"
													? "bg-emerald-500/10 text-emerald-600 border-emerald-500/20"
													: "bg-amber-500/10 text-amber-600 border-amber-500/20"
											}
										>
											{dep.status}
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