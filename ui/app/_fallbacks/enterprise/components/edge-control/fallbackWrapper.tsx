import React from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ShieldCheck, CheckCircle2 } from "lucide-react";

interface EdgeControlFallbackViewProps {
	icon: React.ReactNode;
	title: string;
	description: string;
	readmeLink: string;
	testIdPrefix?: string;
}

export default function EdgeControlFallbackView({ icon, title, description, readmeLink, testIdPrefix }: EdgeControlFallbackViewProps) {
	return (
		<div className="flex h-full min-h-[60vh] w-full flex-col items-center justify-center text-center p-6" data-testid={testIdPrefix}>
			<div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-primary/10 text-primary mb-4">
				{icon}
			</div>
			<div className="flex items-center gap-2 mb-2">
				<h2 className="text-xl font-bold tracking-tight">{title}</h2>
				<Badge variant="outline" className="bg-emerald-500/10 text-emerald-600 border-emerald-500/20">
					Active in SplitGate
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
					Documentation
				</Button>
				<Button size="sm" onClick={() => window.location.href = "/workspace/cluster"}>
					View Gateway Nodes
				</Button>
			</div>
		</div>
	);
}