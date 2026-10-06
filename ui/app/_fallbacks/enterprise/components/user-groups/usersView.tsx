import React, { useState } from "react";
import { Users, Plus, CheckCircle2, ShieldCheck, Mail, KeyRound, Search, DollarSign } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { toast } from "sonner";

interface EnterpriseUser {
	id: string;
	name: string;
	email: string;
	role: "Admin" | "Operator" | "Developer" | "Auditor";
	team: string;
	spend: string;
	budget: string;
	status: "Active" | "Invited" | "Suspended";
}

const INITIAL_USERS: EnterpriseUser[] = [
	{
		id: "usr-1",
		name: "Tyson Goulding",
		email: "tyson@splitgate.io",
		role: "Admin",
		team: "Core Platform",
		spend: "$124.50",
		budget: "$2,000",
		status: "Active",
	},
	{
		id: "usr-2",
		name: "Sarah Chen",
		email: "sarah.chen@splitgate.io",
		role: "Operator",
		team: "Platform SRE",
		spend: "$88.20",
		budget: "$1,000",
		status: "Active",
	},
	{
		id: "usr-3",
		name: "Marcus Aurelius",
		email: "marcus@splitgate.io",
		role: "Developer",
		team: "AI Research",
		spend: "$412.00",
		budget: "$1,500",
		status: "Active",
	},
	{
		id: "usr-4",
		name: "Elena Rostova",
		email: "elena@splitgate.io",
		role: "Auditor",
		team: "InfoSec & Compliance",
		spend: "$0.00",
		budget: "$200",
		status: "Active",
	},
	{
		id: "usr-5",
		name: "David Kim",
		email: "david.kim@splitgate.io",
		role: "Developer",
		team: "Customer Support Automation",
		spend: "$54.10",
		budget: "$500",
		status: "Active",
	},
];

export default function UsersView() {
	const [users, setUsers] = useState<EnterpriseUser[]>(INITIAL_USERS);
	const [search, setSearch] = useState("");
	const [isInviting, setIsInviting] = useState(false);
	const [inviteEmail, setInviteEmail] = useState("");
	const [inviteName, setInviteName] = useState("");
	const [inviteRole, setInviteRole] = useState<EnterpriseUser["role"]>("Developer");

	const filtered = users.filter(
		(u) =>
			u.name.toLowerCase().includes(search.toLowerCase()) ||
			u.email.toLowerCase().includes(search.toLowerCase()) ||
			u.team.toLowerCase().includes(search.toLowerCase())
	);

	const handleInvite = () => {
		if (!inviteEmail || !inviteName) {
			toast.error("Please provide both name and email");
			return;
		}
		const newUser: EnterpriseUser = {
			id: `usr-${Date.now()}`,
			name: inviteName,
			email: inviteEmail,
			role: inviteRole,
			team: "Engineering",
			spend: "$0.00",
			budget: "$500",
			status: "Invited",
		};
		setUsers([...users, newUser]);
		setInviteEmail("");
		setInviteName("");
		setIsInviting(false);
		toast.success(`Invitation sent to ${inviteEmail}`);
	};

	return (
		<div className="space-y-6">
			<div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b pb-4">
				<div className="flex items-center gap-3">
					<div className="flex h-12 w-12 items-center justify-center rounded-xl bg-blue-500/10 text-blue-600 dark:text-blue-400">
						<Users className="h-6 w-6" />
					</div>
					<div>
						<div className="flex items-center gap-2">
							<h1 className="text-xl font-bold tracking-tight">Enterprise User Directory</h1>
							<Badge variant="outline" className="bg-emerald-500/10 text-emerald-600 border-emerald-500/20">
								{users.length} Users Active
							</Badge>
						</div>
						<p className="text-sm text-muted-foreground">
							Provision gateway access, assign RBAC roles, allocate monthly token budgets, and view individual consumption.
						</p>
					</div>
				</div>

				<div className="flex items-center gap-2">
					<div className="w-full sm:w-64">
						<Input
							placeholder="Search users..."
							value={search}
							onChange={(e) => setSearch(e.target.value)}
						/>
					</div>
					<Button onClick={() => setIsInviting(!isInviting)}>
						<Plus className="mr-1.5 h-4 w-4" />
						Invite User
					</Button>
				</div>
			</div>

			{isInviting && (
				<Card className="border-primary/40 bg-accent/20">
					<CardHeader className="pb-3">
						<CardTitle className="text-base">Invite Enterprise Member</CardTitle>
						<CardDescription>Assign an RBAC role and dispatch an onboarding email link.</CardDescription>
					</CardHeader>
					<CardContent className="space-y-4">
						<div className="grid grid-cols-1 md:grid-cols-3 gap-4">
							<div className="space-y-1.5">
								<label className="text-xs font-semibold text-muted-foreground">Full Name</label>
								<Input
									placeholder="Alex Morgan"
									value={inviteName}
									onChange={(e) => setInviteName(e.target.value)}
								/>
							</div>
							<div className="space-y-1.5">
								<label className="text-xs font-semibold text-muted-foreground">Work Email</label>
								<Input
									placeholder="alex@splitgate.io"
									value={inviteEmail}
									onChange={(e) => setInviteEmail(e.target.value)}
								/>
							</div>
							<div className="space-y-1.5">
								<label className="text-xs font-semibold text-muted-foreground">RBAC Role</label>
								<select
									value={inviteRole}
									onChange={(e) => setInviteRole(e.target.value as any)}
									className="w-full rounded-md border bg-background px-3 py-2 text-sm shadow-sm focus:outline-none focus:ring-1 focus:ring-ring"
								>
									<option value="Admin">Admin (Full Control)</option>
									<option value="Operator">Operator (Deploy & Configure)</option>
									<option value="Developer">Developer (Issue Keys & Execute)</option>
									<option value="Auditor">Auditor (Read-Only Logs)</option>
								</select>
							</div>
						</div>
						<div className="flex justify-end gap-2">
							<Button variant="outline" size="sm" onClick={() => setIsInviting(false)}>
								Cancel
							</Button>
							<Button size="sm" onClick={handleInvite}>
								Send Invite
							</Button>
						</div>
					</CardContent>
				</Card>
			)}

			<Card>
				<CardHeader className="pb-2">
					<CardTitle className="text-base">Users & Access Allocations</CardTitle>
				</CardHeader>
				<CardContent>
					<Table>
						<TableHeader>
							<TableRow>
								<TableHead>User</TableHead>
								<TableHead>Role</TableHead>
								<TableHead>Team</TableHead>
								<TableHead>Spend / Budget</TableHead>
								<TableHead className="text-right">Status</TableHead>
							</TableRow>
						</TableHeader>
						<TableBody>
							{filtered.map((user) => (
								<TableRow key={user.id}>
									<TableCell>
										<div>
											<div className="font-semibold text-sm">{user.name}</div>
											<div className="text-xs text-muted-foreground">{user.email}</div>
										</div>
									</TableCell>
									<TableCell>
										<Badge variant="outline" className="font-medium text-xs">
											{user.role}
										</Badge>
									</TableCell>
									<TableCell className="text-xs text-muted-foreground">{user.team}</TableCell>
									<TableCell>
										<span className="text-xs font-medium">{user.spend}</span>
										<span className="text-xs text-muted-foreground"> / {user.budget}</span>
									</TableCell>
									<TableCell className="text-right">
										<Badge
											variant="outline"
											className={
												user.status === "Active"
													? "bg-emerald-500/10 text-emerald-600 border-emerald-500/20"
													: "bg-blue-500/10 text-blue-600 border-blue-500/20"
											}
										>
											{user.status}
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