import React, { useState } from "react";
import { Building2, Plus, CheckCircle2, ShieldCheck, DollarSign, Layers } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { toast } from "sonner";

interface BusinessUnit {
	id: string;
	name: string;
	code: string;
	head: string;
	spend: number;
	budget: number;
	teamsCount: number;
	status: "Active" | "Review Required";
}

const INITIAL_UNITS: BusinessUnit[] = [
	{
		id: "bu-1",
		name: "Engineering & Platform",
		code: "BU-ENG-01",
		head: "Alexandre Dumas",
		spend: 4210.0,
		budget: 15000.0,
		teamsCount: 4,
		status: "Active",
	},
	{
		id: "bu-2",
		name: "Product & Growth",
		code: "BU-PROD-02",
		head: "Claire Bennet",
		spend: 2210.0,
		budget: 10000.0,
		teamsCount: 3,
		status: "Active",
	},
	{
		id: "bu-3",
		name: "Data Science & Applied AI",
		code: "BU-AI-03",
		head: "Dr. Evelyn Reed",
		spend: 3840.0,
		budget: 12000.0,
		teamsCount: 2,
		status: "Active",
	},
];

export function BusinessUnitsView() {
	const [units, setUnits] = useState<BusinessUnit[]>(INITIAL_UNITS);
	const [isCreating, setIsCreating] = useState(false);
	const [unitName, setUnitName] = useState("");
	const [unitCode, setUnitCode] = useState("");
	const [unitHead, setUnitHead] = useState("");
	const [unitBudget, setUnitBudget] = useState("10000");

	const handleCreate = () => {
		if (!unitName) {
			toast.error("Please enter a business unit name");
			return;
		}
		const newUnit: BusinessUnit = {
			id: `bu-${Date.now()}`,
			name: unitName,
			code: unitCode || "BU-CUSTOM",
			head: unitHead || "Unassigned",
			spend: 0.0,
			budget: parseFloat(unitBudget) || 10000,
			teamsCount: 1,
			status: "Active",
		};
		setUnits([...units, newUnit]);
		setUnitName("");
		setUnitCode("");
		setUnitHead("");
		setIsCreating(false);
		toast.success(`Business Unit "${unitName}" created successfully.`);
	};

	return (
		<div className="space-y-6">
			<div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b pb-4">
				<div className="flex items-center gap-3">
					<div className="flex h-12 w-12 items-center justify-center rounded-xl bg-purple-500/10 text-purple-600 dark:text-purple-400">
						<Building2 className="h-6 w-6" />
					</div>
					<div>
						<div className="flex items-center gap-2">
							<h1 className="text-xl font-bold tracking-tight">Business Units Governance</h1>
							<Badge variant="outline" className="bg-emerald-500/10 text-emerald-600 border-emerald-500/20">
								{units.length} Business Units Active
							</Badge>
						</div>
						<p className="text-sm text-muted-foreground">
							Structure departments into top-level business units with dedicated cost centers and aggregated spend ceilings.
						</p>
					</div>
				</div>

				<Button onClick={() => setIsCreating(!isCreating)}>
					<Plus className="mr-1.5 h-4 w-4" />
					Add Business Unit
				</Button>
			</div>

			{isCreating && (
				<Card className="border-primary/40 bg-accent/20">
					<CardHeader className="pb-3">
						<CardTitle className="text-base">Create Business Unit</CardTitle>
						<CardDescription>Allocate departmental budget and cost center identifier.</CardDescription>
					</CardHeader>
					<CardContent className="space-y-4">
						<div className="grid grid-cols-1 md:grid-cols-4 gap-4">
							<div className="space-y-1.5">
								<label className="text-xs font-semibold text-muted-foreground">Unit Name</label>
								<Input
									placeholder="e.g. Enterprise Sales & Solutions"
									value={unitName}
									onChange={(e) => setUnitName(e.target.value)}
								/>
							</div>
							<div className="space-y-1.5">
								<label className="text-xs font-semibold text-muted-foreground">Unit Code</label>
								<Input
									placeholder="BU-SALES-04"
									value={unitCode}
									onChange={(e) => setUnitCode(e.target.value)}
								/>
							</div>
							<div className="space-y-1.5">
								<label className="text-xs font-semibold text-muted-foreground">Department Head</label>
								<Input
									placeholder="e.g. Rachel Green"
									value={unitHead}
									onChange={(e) => setUnitHead(e.target.value)}
								/>
							</div>
							<div className="space-y-1.5">
								<label className="text-xs font-semibold text-muted-foreground">Monthly Budget ($)</label>
								<Input
									placeholder="10000"
									value={unitBudget}
									onChange={(e) => setUnitBudget(e.target.value)}
								/>
							</div>
						</div>
						<div className="flex justify-end gap-2">
							<Button variant="outline" size="sm" onClick={() => setIsCreating(false)}>
								Cancel
							</Button>
							<Button size="sm" onClick={handleCreate}>
								Create Unit
							</Button>
						</div>
					</CardContent>
				</Card>
			)}

			<Card>
				<CardHeader className="pb-2">
					<CardTitle className="text-base">Configured Business Units</CardTitle>
				</CardHeader>
				<CardContent>
					<Table>
						<TableHeader>
							<TableRow>
								<TableHead>Business Unit</TableHead>
								<TableHead>Code</TableHead>
								<TableHead>Head of Unit</TableHead>
								<TableHead>Spend / Monthly Budget</TableHead>
								<TableHead>Teams</TableHead>
								<TableHead className="text-right">Status</TableHead>
							</TableRow>
						</TableHeader>
						<TableBody>
							{units.map((unit) => {
								const pct = Math.min(100, Math.round((unit.spend / unit.budget) * 100));
								return (
									<TableRow key={unit.id}>
										<TableCell className="font-semibold text-sm">{unit.name}</TableCell>
										<TableCell>
											<Badge variant="outline">{unit.code}</Badge>
										</TableCell>
										<TableCell className="text-xs text-muted-foreground">{unit.head}</TableCell>
										<TableCell>
											<div className="space-y-1 w-44">
												<div className="flex justify-between text-xs">
													<span className="font-medium">${unit.spend.toLocaleString()}</span>
													<span className="text-muted-foreground">${unit.budget.toLocaleString()}</span>
												</div>
												<div className="h-1.5 w-full bg-secondary rounded-full overflow-hidden">
													<div
														className={`h-full ${pct > 80 ? "bg-amber-500" : "bg-emerald-500"}`}
														style={{ width: `${pct}%` }}
													/>
												</div>
											</div>
										</TableCell>
										<TableCell className="text-xs text-muted-foreground">{unit.teamsCount} teams</TableCell>
										<TableCell className="text-right">
											<Badge variant="outline" className="bg-emerald-500/10 text-emerald-600 border-emerald-500/20">
												{unit.status}
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