import React from "react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { ArrowUpRight, CheckCircle2, ShieldCheck } from "lucide-react";

interface Props {
	className?: string;
	icon: React.ReactNode;
	title: string;
	description: string;
	readmeLink: string;
	align?: "middle" | "top";
	testIdPrefix?: string;
}

export default function ContactUsView({ icon, title, description, className, readmeLink, align = "middle", testIdPrefix }: Props) {
	// Clean up any upstream upstream paywall phrasing
	const cleanTitle = title.replace(/^Unlock\s+/i, "SplitGate ").replace(/\s+for\s+better\s+/i, " — ");
	const cleanDesc = description.includes("enterprise license")
		? "SplitGate Enterprise features are active and managed directly by your SplitGate cluster node. You can configure rules, policies, and integrations below."
		: description;

	return (
		<div className={cn("flex flex-col items-center gap-4 text-center p-6", align === "middle" ? "justify-center" : "justify-start", className)}>
			<div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-primary/10 text-primary mb-2">
				{icon}
			</div>
			<div className="flex flex-col items-center gap-1.5">
				<div className="flex items-center gap-2">
					<h1 className="text-xl font-bold tracking-tight">{cleanTitle}</h1>
					<Badge variant="outline" className="bg-emerald-500/10 text-emerald-600 border-emerald-500/20 text-xs">
						<CheckCircle2 className="mr-1 h-3 w-3" />
						Enterprise Enabled
					</Badge>
				</div>
				<div className="text-muted-foreground mt-1 max-w-[600px] text-sm font-normal">
					{cleanDesc}
				</div>
				<div className="mx-auto flex flex-row items-center gap-2 mt-4">
					<Button
						variant="outline"
						size="sm"
						data-testid={testIdPrefix ? `${testIdPrefix}-read-more` : undefined}
						onClick={() => {
							window.open(readmeLink, "_blank", "noopener,noreferrer");
						}}
					>
						Documentation <ArrowUpRight className="ml-1 h-3 w-3" />
					</Button>
					<Button
						size="sm"
						data-testid={testIdPrefix ? `${testIdPrefix}-book-demo` : undefined}
						onClick={() => {
							window.location.href = "/workspace/cluster";
						}}
					>
						<ShieldCheck className="mr-1.5 h-3.5 w-3.5" />
						Cluster Status
					</Button>
				</div>
			</div>
		</div>
	);
}