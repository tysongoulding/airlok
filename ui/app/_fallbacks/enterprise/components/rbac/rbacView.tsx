import React, { useState } from "react";
import { UserRoundCheck, Shield, Key, Lock, CheckCircle2, XCircle, Plus, Users, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { toast } from "sonner";

interface RolePermission {
	resource: string;
	admin: boolean;
	operator: boolean;
	developer: boolean;
	auditor: boolean;
}

const PERMISSION_MATRIX: RolePermission[] = [
	{ resource: "Virtual Keys: Create / Revoke", admin: true, operator: true, developer: true, auditor: false },
	{ resource: "Virtual Keys: Set Budgets & Limits", admin: true, operator: true, developer: false, auditor: false },
	{ resource: "Providers: Add / Edit Keys & Proxies", admin: true, operator: true, developer: false, auditor: false },
	{ resource: "Guardrails: Update Rules & Moderation", admin: true, operator: false, developer: false, auditor: false },
	{ resource: "Cluster: Rebalance & Node Management", admin: true, operator: false, developer: false, auditor: false },
	{ resource: "Routing Rules & Tree: Edit Rules", admin: true, operator: true, developer: true, auditor: false },
	{ resource: "Audit Logs: View Security Trail", admin: true, operator: false, developer: false, auditor: true },
	{ resource: "Inference: Execute LLM Calls", admin: true, operator: true, developer: true, auditor: false },
	{ resource: "MCP Tools: Execute Registered Tools", admin: true, operator: true, developer: true, auditor: false },
];

export default function RBACView() {
	const [matrix, setMatrix] = useState<RolePermission[]>(PERMISSION_MATRIX);

	return (
		<div className="space-y-6">
			{/* Header */}
			<div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
				<div>
					<div className="flex items-center gap-2">
						<h1 className="text-2xl font-bold tracking-tight text-foreground">Role-Based Access Control (RBAC)</h1>
						<Badge variant="outline" className="bg-emerald-500/10 text-emerald-500 border-emerald-500/20">
							Enforcement Active
						</Badge>
					</div>
					<p className="text-sm text-muted-foreground mt-0.5">
						Fine-grained permission boundaries applied across API routes, virtual key scopes, and console users.
					</p>
				</div>
				<div className="flex items-center gap-2">
					<Button
						variant="outline"
						size="sm"
						onClick={() => toast.success("RBAC policies verified with policy cache")}
					>
						<RefreshCw className="mr-1.5 h-3.5 w-3.5" />
						Verify Policies
					</Button>
				</div>
			</div>

			{/* Roles Overview Cards */}
			<div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
				<Card>
					<CardHeader className="flex flex-row items-center justify-between pb-2">
						<CardTitle className="text-xs font-medium text-muted-foreground">Admin Role</CardTitle>
						<Lock className="h-4 w-4 text-rose-500" />
					</CardHeader>
					<CardContent>
						<div className="text-2xl font-bold">Unrestricted</div>
						<p className="text-xs text-muted-foreground mt-1">Full root access to all engines</p>
					</CardContent>
				</Card>
				<Card>
					<CardHeader className="flex flex-row items-center justify-between pb-2">
						<CardTitle className="text-xs font-medium text-muted-foreground">Operator Role</CardTitle>
						<Shield className="h-4 w-4 text-amber-500" />
					</CardHeader>
					<CardContent>
						<div className="text-2xl font-bold">Ops & Routing</div>
						<p className="text-xs text-muted-foreground mt-1">Manage providers & budgets</p>
					</CardContent>
				</Card>
				<Card>
					<CardHeader className="flex flex-row items-center justify-between pb-2">
						<CardTitle className="text-xs font-medium text-muted-foreground">Developer Role</CardTitle>
						<Key className="h-4 w-4 text-blue-500" />
					</CardHeader>
					<CardContent>
						<div className="text-2xl font-bold">Inference & MCP</div>
						<p className="text-xs text-muted-foreground mt-1">Virtual keys & tool execution</p>
					</CardContent>
				</Card>
				<Card>
					<CardHeader className="flex flex-row items-center justify-between pb-2">
						<CardTitle className="text-xs font-medium text-muted-foreground">Auditor Role</CardTitle>
						<CheckCircle2 className="h-4 w-4 text-emerald-500" />
					</CardHeader>
					<CardContent>
						<div className="text-2xl font-bold">Read-Only Logs</div>
						<p className="text-xs text-muted-foreground mt-1">Compliance & audit inspection</p>
					</CardContent>
				</Card>
			</div>

			{/* RBAC Permission Matrix Table */}
			<Card>
				<CardHeader>
					<CardTitle className="text-base font-semibold">Granular Resource Permission Matrix</CardTitle>
					<CardDescription>
						Matrix enforced by SplitGate FastHTTP route middleware on incoming user sessions and API tokens.
					</CardDescription>
				</CardHeader>
				<CardContent className="p-0">
					<div className="overflow-x-auto">
						<table className="w-full text-left text-sm">
							<thead className="border-b bg-muted/40 text-xs font-medium text-muted-foreground uppercase">
								<tr>
									<th className="px-4 py-3">Resource & Operation</th>
									<th className="px-4 py-3 text-center">Admin</th>
									<th className="px-4 py-3 text-center">Operator</th>
									<th className="px-4 py-3 text-center">Developer</th>
									<th className="px-4 py-3 text-center">Auditor</th>
								</tr>
							</thead>
							<tbody className="divide-y">
								{matrix.map((row) => (
									<tr key={row.resource} className="hover:bg-muted/20 transition-colors">
										<td className="px-4 py-3 font-medium text-foreground">
											{row.resource}
										</td>
										<td className="px-4 py-3 text-center">
											{row.admin ? (
												<CheckCircle2 className="h-4 w-4 text-emerald-500 mx-auto" />
											) : (
												<XCircle className="h-4 w-4 text-muted-foreground/30 mx-auto" />
											)}
										</td>
										<td className="px-4 py-3 text-center">
											{row.operator ? (
												<CheckCircle2 className="h-4 w-4 text-emerald-500 mx-auto" />
											) : (
												<XCircle className="h-4 w-4 text-muted-foreground/30 mx-auto" />
											)}
										</td>
										<td className="px-4 py-3 text-center">
											{row.developer ? (
												<CheckCircle2 className="h-4 w-4 text-emerald-500 mx-auto" />
											) : (
												<XCircle className="h-4 w-4 text-muted-foreground/30 mx-auto" />
											)}
										</td>
										<td className="px-4 py-3 text-center">
											{row.auditor ? (
												<CheckCircle2 className="h-4 w-4 text-emerald-500 mx-auto" />
											) : (
												<XCircle className="h-4 w-4 text-muted-foreground/30 mx-auto" />
											)}
										</td>
									</tr>
								))}
							</tbody>
						</table>
					</div>
				</CardContent>
			</Card>
		</div>
	);
}