import React, { useState } from "react";
import { Network, Building2, Users, KeyRound, ChevronRight, ChevronDown, ShieldCheck, DollarSign } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";

interface OrgNode {
	id: string;
	title: string;
	type: "root" | "unit" | "team" | "key";
	budget: string;
	spend: string;
	children?: OrgNode[];
}

const ORG_TREE: OrgNode = {
	id: "root-1",
	title: "SplitGate Enterprise Organization",
	type: "root",
	budget: "$25,000 / mo",
	spend: "$6,420",
	children: [
		{
			id: "bu-1",
			title: "Engineering & Platform Unit",
			type: "unit",
			budget: "$15,000 / mo",
			spend: "$4,210",
			children: [
				{
					id: "team-1",
					title: "Core Platform Team",
					type: "team",
					budget: "$8,000 / mo",
					spend: "$2,840",
					children: [
						{ id: "vk-1", title: "vk_platform_prod (GPT-4o / Claude 3.5)", type: "key", budget: "$5,000", spend: "$1,920" },
						{ id: "vk-2", title: "vk_platform_staging (Llama 3.3)", type: "key", budget: "$3,000", spend: "$920" },
					],
				},
				{
					id: "team-2",
					title: "AI Research & Data Science",
					type: "team",
					budget: "$7,000 / mo",
					spend: "$1,370",
					children: [
						{ id: "vk-3", title: "vk_research_evals (Bedrock / Gemini)", type: "key", budget: "$7,000", spend: "$1,370" },
					],
				},
			],
		},
		{
			id: "bu-2",
			title: "Product & Growth Unit",
			type: "unit",
			budget: "$10,000 / mo",
			spend: "$2,210",
			children: [
				{
					id: "team-3",
					title: "Customer Support Automation",
					type: "team",
					budget: "$6,000 / mo",
					spend: "$1,450",
					children: [
						{ id: "vk-4", title: "vk_support_bot_prod (GPT-4o mini)", type: "key", budget: "$6,000", spend: "$1,450" },
					],
				},
				{
					id: "team-4",
					title: "Marketing Copy Generation",
					type: "team",
					budget: "$4,000 / mo",
					spend: "$760",
					children: [
						{ id: "vk-5", title: "vk_marketing_agent (Claude 3.5 Sonnet)", type: "key", budget: "$4,000", spend: "$760" },
					],
				},
			],
		},
	],
};

function TreeNode({ node, depth = 0 }: { node: OrgNode; depth?: number }) {
	const [isOpen, setIsOpen] = useState(true);
	const hasChildren = node.children && node.children.length > 0;

	return (
		<div className="space-y-2">
			<div
				className={`flex items-center justify-between p-3 rounded-lg border transition-all ${
					node.type === "root"
						? "bg-primary/10 border-primary/30"
						: node.type === "unit"
						? "bg-accent/40 border-border ml-4"
						: node.type === "team"
						? "bg-card ml-8 border-border"
						: "bg-muted/40 ml-12 border-dashed border-border"
				}`}
			>
				<div className="flex items-center gap-2.5">
					{hasChildren ? (
						<button
							type="button"
							onClick={() => setIsOpen(!isOpen)}
							className="p-1 hover:bg-muted rounded text-muted-foreground"
						>
							{isOpen ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
						</button>
					) : (
						<div className="w-6" />
					)}

					{node.type === "root" && <Network className="h-5 w-5 text-primary" />}
					{node.type === "unit" && <Building2 className="h-4 w-4 text-purple-500" />}
					{node.type === "team" && <Users className="h-4 w-4 text-blue-500" />}
					{node.type === "key" && <KeyRound className="h-4 w-4 text-amber-500" />}

					<div>
						<div className="font-semibold text-sm">{node.title}</div>
						<div className="text-xs text-muted-foreground capitalize">{node.type} Node</div>
					</div>
				</div>

				<div className="flex items-center gap-3">
					<div className="text-right text-xs">
						<div className="font-medium">{node.spend} spent</div>
						<div className="text-muted-foreground">{node.budget} limit</div>
					</div>
					<Badge
						variant="outline"
						className={
							node.type === "root"
								? "bg-primary/20 text-primary border-primary/40 text-[10px]"
								: "bg-secondary text-secondary-foreground text-[10px]"
						}
					>
						{node.type.toUpperCase()}
					</Badge>
				</div>
			</div>

			{hasChildren && isOpen && (
				<div className="space-y-2 border-l-2 border-border/50 pl-2">
					{node.children!.map((child) => (
						<TreeNode key={child.id} node={child} depth={depth + 1} />
					))}
				</div>
			)}
		</div>
	);
}

export function OrgChartView() {
	return (
		<div className="space-y-6">
			<div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b pb-4">
				<div className="flex items-center gap-3">
					<div className="flex h-12 w-12 items-center justify-center rounded-xl bg-purple-500/10 text-purple-600 dark:text-purple-400">
						<Network className="h-6 w-6" />
					</div>
					<div>
						<div className="flex items-center gap-2">
							<h1 className="text-xl font-bold tracking-tight">Organization Governance Hierarchy</h1>
							<Badge variant="outline" className="bg-emerald-500/10 text-emerald-600 border-emerald-500/20">
								Hierarchy Synchronized
							</Badge>
						</div>
						<p className="text-sm text-muted-foreground">
							Visualize organizational units, teams, and downlinked virtual key budgets across your enterprise.
						</p>
					</div>
				</div>
			</div>

			<Card>
				<CardHeader className="pb-3">
					<CardTitle className="text-base">Organizational Tree</CardTitle>
					<CardDescription>Click any parent node to collapse or expand its organizational subtree.</CardDescription>
				</CardHeader>
				<CardContent className="space-y-3">
					<TreeNode node={ORG_TREE} />
				</CardContent>
			</Card>
		</div>
	);
}