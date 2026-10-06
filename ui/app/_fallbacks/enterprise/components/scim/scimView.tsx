import React, { useState } from "react";
import { BookUser, ShieldCheck, Key, CheckCircle2, Copy, RefreshCw, ExternalLink } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { toast } from "sonner";

export default function SCIMView() {
	const [protocol, setProtocol] = useState<"SAML" | "OIDC">("SAML");
	const [jitEnabled, setJitEnabled] = useState(true);
	const [scimEnabled, setScimEnabled] = useState(true);

	const metadataUrl = "http://192.168.144.110:8080/api/v1/enterprise/sso/saml/metadata";
	const acsUrl = "http://192.168.144.110:8080/api/v1/enterprise/sso/saml/acs";

	const copyToClipboard = (text: string, label: string) => {
		navigator.clipboard.writeText(text);
		toast.success(`${label} copied to clipboard`);
	};

	return (
		<div className="space-y-6">
			{/* Header */}
			<div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
				<div>
					<div className="flex items-center gap-2">
						<h1 className="text-2xl font-bold tracking-tight text-foreground">Enterprise SSO & SCIM Provisioning</h1>
						<Badge variant="outline" className="bg-emerald-500/10 text-emerald-500 border-emerald-500/20">
							Active
						</Badge>
					</div>
					<p className="text-sm text-muted-foreground mt-0.5">
						Federated single sign-on (SAML 2.0 / OIDC) and SCIM 2.0 automated directory lifecycle management.
					</p>
				</div>
				<div className="flex items-center gap-2">
					<Button
						variant="outline"
						size="sm"
						onClick={() => window.open(metadataUrl, "_blank")}
					>
						<ExternalLink className="mr-1.5 h-3.5 w-3.5" />
						View SAML Metadata
					</Button>
				</div>
			</div>

			{/* Service Provider (SP) Endpoints */}
			<Card>
				<CardHeader>
					<CardTitle className="text-base font-semibold">SplitGate Service Provider (SP) Credentials</CardTitle>
					<CardDescription>
						Provide these endpoints to your Identity Provider (Okta, Entra ID, Keycloak, Ping Identity).
					</CardDescription>
				</CardHeader>
				<CardContent className="space-y-4">
					<div className="grid gap-4 sm:grid-cols-2">
						<div className="space-y-1.5">
							<label className="text-xs font-medium text-muted-foreground">Entity ID / Issuer</label>
							<div className="flex gap-2">
								<Input readOnly value="urn:splitgate:ai:gateway" className="font-mono text-xs bg-muted/40" />
								<Button variant="outline" size="sm" onClick={() => copyToClipboard("urn:splitgate:ai:gateway", "Entity ID")}>
									<Copy className="h-3.5 w-3.5" />
								</Button>
							</div>
						</div>
						<div className="space-y-1.5">
							<label className="text-xs font-medium text-muted-foreground">Assertion Consumer Service (ACS) URL</label>
							<div className="flex gap-2">
								<Input readOnly value={acsUrl} className="font-mono text-xs bg-muted/40" />
								<Button variant="outline" size="sm" onClick={() => copyToClipboard(acsUrl, "ACS URL")}>
									<Copy className="h-3.5 w-3.5" />
								</Button>
							</div>
						</div>
					</div>
				</CardContent>
			</Card>

			{/* Provisioning & Mapping Settings */}
			<div className="grid gap-4 md:grid-cols-2">
				<Card>
					<CardHeader>
						<div className="flex items-center justify-between">
							<CardTitle className="text-base font-semibold">Just-In-Time (JIT) Provisioning</CardTitle>
							<Switch checked={jitEnabled} onCheckedChange={setJitEnabled} />
						</div>
						<CardDescription className="text-xs">
							Automatically create local users and assign roles upon their first successful SSO login.
						</CardDescription>
					</CardHeader>
					<CardContent className="space-y-3 pt-0 text-xs">
						<div className="flex justify-between items-center py-2 border-b">
							<span className="text-muted-foreground">Default Assigned Role:</span>
							<Badge variant="outline">Developer</Badge>
						</div>
						<div className="flex justify-between items-center py-2">
							<span className="text-muted-foreground">Sync User Groups on Every Login:</span>
							<Badge className="bg-emerald-500/10 text-emerald-500 border-emerald-500/20">Enabled</Badge>
						</div>
					</CardContent>
				</Card>

				<Card>
					<CardHeader>
						<div className="flex items-center justify-between">
							<CardTitle className="text-base font-semibold">SCIM 2.0 Directory Sync</CardTitle>
							<Switch checked={scimEnabled} onCheckedChange={setScimEnabled} />
						</div>
						<CardDescription className="text-xs">
							Sync user lifecycles, team memberships, and immediate deprovisioning from Okta / Entra.
						</CardDescription>
					</CardHeader>
					<CardContent className="space-y-3 pt-0 text-xs">
						<div className="space-y-1">
							<span className="text-muted-foreground">Base SCIM URL:</span>
							<div className="font-mono bg-muted/50 p-2 rounded border border-border/50 truncate">
								http://192.168.144.110:8080/scim/v2
							</div>
						</div>
						<div className="flex justify-between items-center pt-2">
							<span className="text-muted-foreground">Status:</span>
							<Badge className="bg-emerald-500/10 text-emerald-500 border-emerald-500/20">Listening</Badge>
						</div>
					</CardContent>
				</Card>
			</div>
		</div>
	);
}