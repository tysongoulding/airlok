import React from "react";
import { Siren, CheckCircle2, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

type AlertingPlaceholderViewProps = {
	title: string;
	description: string;
	testIdPrefix: string;
	readmeLink?: string;
};

export default function AlertingPlaceholderView({
	title,
	description,
	testIdPrefix,
	readmeLink = "https://docs.splitgate.io/features/alerting",
}: AlertingPlaceholderViewProps) {
	return (
		<div className="flex h-full min-h-[60vh] w-full flex-col items-center justify-center text-center p-6" data-testid={testIdPrefix}>
			<div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-primary/10 text-primary mb-4">
				<Siren className="h-8 w-8" />
			</div>
			<div className="flex items-center gap-2 mb-2">
				<h2 className="text-xl font-bold tracking-tight">{title}</h2>
				<Badge variant="outline" className="bg-emerald-500/10 text-emerald-600 border-emerald-500/20">
					Enterprise Active
				</Badge>
			</div>
			<p className="max-w-md text-sm text-muted-foreground mb-6">
				{description}
			</p>
			<div className="flex items-center gap-3">
				<Button
					variant="outline"
					size="sm"
					onClick={() => window.open(readmeLink, "_blank", "noopener,noreferrer")}
				>
					View Alerting Guide
				</Button>
				<Button size="sm" onClick={() => window.location.href = "/workspace/alerting/rules"}>
					Manage Rules
				</Button>
			</div>
		</div>
	);
}