import React, { useState } from "react";
import { Users, Award, TrendingUp, DollarSign, Zap } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

interface UserRanking {
	rank: number;
	name: string;
	email: string;
	tokensTotal: string;
	requestsTotal: number;
	spendTotal: string;
	topModel: string;
}

const RANKINGS: UserRanking[] = [
	{
		rank: 1,
		name: "Marcus Aurelius",
		email: "marcus@splitgate.io",
		tokensTotal: "18.4M",
		requestsTotal: 4120,
		spendTotal: "$412.00",
		topModel: "claude-3-5-sonnet",
	},
	{
		rank: 2,
		name: "Tyson Goulding",
		email: "tyson@splitgate.io",
		tokensTotal: "12.1M",
		requestsTotal: 2840,
		spendTotal: "$124.50",
		topModel: "gpt-4o",
	},
	{
		rank: 3,
		name: "Sarah Chen",
		email: "sarah.chen@splitgate.io",
		tokensTotal: "9.2M",
		requestsTotal: 1910,
		spendTotal: "$88.20",
		topModel: "llama-3.3-70b",
	},
	{
		rank: 4,
		name: "David Kim",
		email: "david.kim@splitgate.io",
		tokensTotal: "5.8M",
		requestsTotal: 1220,
		spendTotal: "$54.10",
		topModel: "gpt-4o-mini",
	},
];

export default function UserRankingsTab() {
	return (
		<div className="space-y-6">
			<div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b pb-4">
				<div className="flex items-center gap-3">
					<div className="flex h-12 w-12 items-center justify-center rounded-xl bg-amber-500/10 text-amber-600 dark:text-amber-400">
						<Award className="h-6 w-6" />
					</div>
					<div>
						<div className="flex items-center gap-2">
							<h1 className="text-xl font-bold tracking-tight">User Consumption Leaderboard</h1>
							<Badge variant="outline" className="bg-emerald-500/10 text-emerald-600 border-emerald-500/20">
								Current Billing Cycle
							</Badge>
						</div>
						<p className="text-sm text-muted-foreground">
							Top token consumers, request volumes, and spend distribution across all active enterprise team members.
						</p>
					</div>
				</div>
			</div>

			<Card>
				<CardHeader className="pb-2">
					<CardTitle className="text-base">Top Consumers</CardTitle>
				</CardHeader>
				<CardContent>
					<Table>
						<TableHeader>
							<TableRow>
								<TableHead className="w-16">Rank</TableHead>
								<TableHead>User</TableHead>
								<TableHead>Total Tokens</TableHead>
								<TableHead>Requests</TableHead>
								<TableHead>Total Spend</TableHead>
								<TableHead className="text-right">Primary Model</TableHead>
							</TableRow>
						</TableHeader>
						<TableBody>
							{RANKINGS.map((user) => (
								<TableRow key={user.rank}>
									<TableCell>
										<span className={`inline-flex items-center justify-center h-6 w-6 rounded-full text-xs font-bold ${
											user.rank === 1 ? "bg-amber-500/20 text-amber-600" :
											user.rank === 2 ? "bg-slate-400/20 text-slate-600" :
											user.rank === 3 ? "bg-orange-500/20 text-orange-600" :
											"text-muted-foreground"
										}`}>
											{user.rank}
										</span>
									</TableCell>
									<TableCell>
										<div>
											<div className="font-semibold text-sm">{user.name}</div>
											<div className="text-xs text-muted-foreground">{user.email}</div>
										</div>
									</TableCell>
									<TableCell className="font-mono text-xs font-medium">{user.tokensTotal}</TableCell>
									<TableCell className="text-xs text-muted-foreground">{user.requestsTotal.toLocaleString()}</TableCell>
									<TableCell className="text-xs font-semibold">{user.spendTotal}</TableCell>
									<TableCell className="text-right">
										<Badge variant="outline" className="font-mono text-[11px]">
											{user.topModel}
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