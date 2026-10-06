import React, { useState } from "react";
import { FolderKanban, Plus, CheckCircle2, DollarSign, Users, KeyRound, Layers, Activity } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { toast } from "sonner";

interface Project {
	id: string;
	name: string;
	slug: string;
	costCenter: string;
	spendCurrent: number;
	spendLimit: number;
	teamsCount: number;
	virtualKeysCount: number;
	status: "Active" | "Budget Warning" | "Paused";
}

const INITIAL_PROJECTS: Project[] = [
	{
		id: "proj-1",
		name: "Customer Support Copilot",
		slug: "cust-copilot-prod",
		costCenter: "CC-9011-CX",
		spendCurrent: 432.8,
		spendLimit: 1500.0,
		teamsCount: 2,
		virtualKeysCount: 3,
		status: "Active",
	},
	{
		id: "proj-2",
		name: "Internal Engineering Agent",
		slug: "eng-agent-sandbox",
		costCenter: "CC-4022-ENG",
		spendCurrent: 812.4,
		spendLimit: 1000.0,
		teamsCount: 5,
		virtualKeysCount: 8,
		status: "Budget Warning",
	},
	{
		id: "proj-3",
		name: "Legal Doc Summarizer",
		slug: "legal-doc-etl",
		costCenter: "CC-1099-LEGAL",
		spendCurrent: 145.2,
		spendLimit: 2000.0,
		teamsCount: 1,
		virtualKeysCount: 2,
		status: "Active",
	},
	{
		id: "proj-4",
		name: "Marketing Content Generator",
		slug: "marketing-ai-studio",
		costCenter: "CC-3033-MKT",
		spendCurrent: 28.5,
		spendLimit: 500.0,
		teamsCount: 2,
		virtualKeysCount: 2,
		status: "Active",
	},
];

export default function ProjectsIndexView() {
	const [projects, setProjects] = useState<Project[]>(INITIAL_PROJECTS);
	const [isCreating, setIsCreating] = useState(false);
	const [newName, setNewName] = useState("");
	const [newCostCenter, setNewCostCenter] = useState("");
	const [newLimit, setNewLimit] = useState("1000");

	const handleCreate = () => {
		if (!newName) {
			toast.error("Please enter a project name");
			return;
		}
		const slug = newName.toLowerCase().replace(/[^a-z0-9]+/g, "-");
		const newProj: Project = {
			id: `proj-${Date.now()}`,
			name: newName,
			slug,
			costCenter: newCostCenter || "CC-GENERAL",
			spendCurrent: 0.0,
			spendLimit: parseFloat(newLimit) || 1000,
			teamsCount: 1,
			virtualKeysCount: 1,
			status: "Active",
		};
		setProjects([...projects, newProj]);
		setNewName("");
		setNewCostCenter("");
		setIsCreating(false);
		toast.success(`Project "${newName}" created successfully.`);
	};

	return (
		<div className="space-y-6">
			<div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b pb-4">
				<div className="flex items-center gap-3">
					<div className="flex h-12 w-12 items-center justify-center rounded-xl bg-purple-500/10 text-purple-600 dark:text-purple-400">
						<FolderKanban className="h-6 w-6" />
					</div>
					<div>
						<div className="flex items-center gap-2">
							<h1 className="text-xl font-bold tracking-tight">Project Governance & Cost Ledgers</h1>
							<Badge variant="outline" className="bg-emerald-500/10 text-emerald-600 border-emerald-500/20">
								{projects.length} Projects Configured
							</Badge>
						</div>
						<p className="text-sm text-muted-foreground">
							Scope virtual keys, teams, and LLM requests into distinct project ledgers for chargeback accounting and spend isolation.
						</p>
					</div>
				</div>

				<Button onClick={() => setIsCreating(!isCreating)}>
					<Plus className="mr-1.5 h-4 w-4" />
					New Project
				</Button>
			</div>

			{isCreating && (
				<Card className="border-primary/40 bg-accent/20">
					<CardHeader className="pb-3">
						<CardTitle className="text-base">Create New Project Ledger</CardTitle>
						<CardDescription>Allocate spend ceilings and bind cost centers to downstream applications.</CardDescription>
					</CardHeader>
					<CardContent className="space-y-4">
						<div className="grid grid-cols-1 md:grid-cols-3 gap-4">
							<div className="space-y-1.5">
								<label className="text-xs font-semibold text-muted-foreground">Project Name</label>
								<Input
									placeholder="e.g. Finance Analytics LLM"
									value={newName}
									onChange={(e) => setNewName(e.target.value)}
								/>
							</div>
							<div className="space-y-1.5">
								<label className="text-xs font-semibold text-muted-foreground">Cost Center ID</label>
								<Input
									placeholder="e.g. CC-7721-FIN"
									value={newCostCenter}
									onChange={(e) => setNewCostCenter(e.target.value)}
								/>
							</div>
							<div className="space-y-1.5">
								<label className="text-xs font-semibold text-muted-foreground">Monthly Budget ($)</label>
								<Input
									placeholder="1000"
									value={newLimit}
									onChange={(e) => setNewLimit(e.target.value)}
								/>
							</div>
						</div>
						<div className="flex justify-end gap-2">
							<Button variant="outline" size="sm" onClick={() => setIsCreating(false)}>
								Cancel
							</Button>
							<Button size="sm" onClick={handleCreate}>
								Create Project
							</Button>
						</div>
					</CardContent>
				</Card>
			)}

			<Card>
				<CardHeader className="pb-2">
					<CardTitle className="text-base">Active Projects</CardTitle>
				</CardHeader>
				<CardContent>
					<Table>
						<TableHeader>
							<TableRow>
								<TableHead>Project</TableHead>
								<TableHead>Cost Center</TableHead>
								<TableHead>Spend / Monthly Limit</TableHead>
								<TableHead>Teams</TableHead>
								<TableHead>Virtual Keys</TableHead>
								<TableHead className="text-right">Status</TableHead>
							</TableRow>
						</TableHeader>
						<TableBody>
							{projects.map((proj) => {
								const pct = Math.min(100, Math.round((proj.spendCurrent / proj.spendLimit) * 100));
								return (
									<TableRow key={proj.id}>
										<TableCell className="font-medium">
											<div>
												<div className="font-semibold">{proj.name}</div>
												<div className="text-xs font-mono text-muted-foreground">{proj.slug}</div>
											</div>
										</TableCell>
										<TableCell>
											<Badge variant="outline">{proj.costCenter}</Badge>
										</TableCell>
										<TableCell>
											<div className="space-y-1 w-48">
												<div className="flex justify-between text-xs">
													<span className="font-medium">${proj.spendCurrent.toFixed(2)}</span>
													<span className="text-muted-foreground">${proj.spendLimit.toFixed(2)}</span>
												</div>
												<div className="h-1.5 w-full bg-secondary rounded-full overflow-hidden">
													<div
														className={`h-full ${
															pct > 80 ? "bg-amber-500" : "bg-emerald-500"
														}`}
														style={{ width: `${pct}%` }}
													/>
												</div>
											</div>
										</TableCell>
										<TableCell className="text-xs text-muted-foreground">{proj.teamsCount} teams</TableCell>
										<TableCell className="text-xs text-muted-foreground">{proj.virtualKeysCount} keys</TableCell>
										<TableCell className="text-right">
											<Badge
												variant="outline"
												className={
													proj.status === "Active"
														? "bg-emerald-500/10 text-emerald-600 border-emerald-500/20"
														: "bg-amber-500/10 text-amber-600 border-amber-500/20"
												}
											>
												{proj.status}
											</Badge>
										</TableCell>
									</TableRow>
								);
							})}
						</TableBody>
					</Table>
				</CardContent>
			</Card>
		</div>
	);
}