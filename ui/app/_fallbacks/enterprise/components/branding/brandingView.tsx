import React, { useState } from "react";
import { Palette, CheckCircle2, Save, Image, Eye, ShieldCheck, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { toast } from "sonner";

export default function BrandingView() {
	const [orgName, setOrgName] = useState("SplitGate");
	const [logoUrl, setLogoUrl] = useState("/images/splitgate-logo.svg");
	const [faviconUrl, setFaviconUrl] = useState("/favicon.ico");
	const [supportUrl, setSupportUrl] = useState("https://support.splitgate.internal");
	const [themeAccent, setThemeAccent] = useState("indigo");
	const [showWatermark, setShowWatermark] = useState(false);
	const [isSaving, setIsSaving] = useState(false);

	const handleSave = () => {
		setIsSaving(true);
		setTimeout(() => {
			setIsSaving(false);
			toast.success("SplitGate enterprise branding updated and applied to UI.");
		}, 500);
	};

	return (
		<div className="space-y-6">
			<div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b pb-4">
				<div className="flex items-center gap-3">
					<div className="flex h-12 w-12 items-center justify-center rounded-xl bg-pink-500/10 text-pink-600 dark:text-pink-400">
						<Palette className="h-6 w-6" />
					</div>
					<div>
						<div className="flex items-center gap-2">
							<h1 className="text-xl font-bold tracking-tight">Enterprise Custom Branding</h1>
							<Badge variant="outline" className="bg-emerald-500/10 text-emerald-600 border-emerald-500/20">
								Custom Theme Active
							</Badge>
						</div>
						<p className="text-sm text-muted-foreground">
							Customize dashboard branding, logos, accent palettes, and white-label the SplitGate portal.
						</p>
					</div>
				</div>

				<Button size="sm" onClick={handleSave} disabled={isSaving}>
					{isSaving ? <RefreshCw className="mr-1.5 h-3.5 w-3.5 animate-spin" /> : <Save className="mr-1.5 h-3.5 w-3.5" />}
					Apply Branding
				</Button>
			</div>

			<div className="grid grid-cols-1 md:grid-cols-2 gap-6">
				<Card>
					<CardHeader>
						<CardTitle className="text-base">Portal Identity</CardTitle>
						<CardDescription>Configure your organization's display name and assets.</CardDescription>
					</CardHeader>
					<CardContent className="space-y-4">
						<div className="space-y-1.5">
							<label className="text-xs font-semibold text-muted-foreground">Organization Display Name</label>
							<Input
								value={orgName}
								onChange={(e) => setOrgName(e.target.value)}
								placeholder="SplitGate"
							/>
						</div>

						<div className="space-y-1.5">
							<label className="text-xs font-semibold text-muted-foreground">Header Logo URL</label>
							<Input
								value={logoUrl}
								onChange={(e) => setLogoUrl(e.target.value)}
								placeholder="/images/custom-logo.svg"
							/>
						</div>

						<div className="space-y-1.5">
							<label className="text-xs font-semibold text-muted-foreground">Favicon URL</label>
							<Input
								value={faviconUrl}
								onChange={(e) => setFaviconUrl(e.target.value)}
								placeholder="/favicon.ico"
							/>
						</div>

						<div className="space-y-1.5">
							<label className="text-xs font-semibold text-muted-foreground">Internal Support URL</label>
							<Input
								value={supportUrl}
								onChange={(e) => setSupportUrl(e.target.value)}
								placeholder="https://help.mycorp.com"
							/>
						</div>

						<div className="border-t pt-3">
							<div className="flex items-center justify-between">
								<div className="space-y-0.5">
									<div className="text-sm font-medium">Show "Powered by SplitGate" Badge</div>
									<div className="text-xs text-muted-foreground">Toggle footer branding badge visibility on public login screens.</div>
								</div>
								<Switch checked={showWatermark} onCheckedChange={setShowWatermark} />
							</div>
						</div>
					</CardContent>
				</Card>

				<div className="space-y-6">
					<Card>
						<CardHeader>
							<CardTitle className="text-base">Color Theme Palette</CardTitle>
							<CardDescription>Select an enterprise color theme for primary buttons and accents.</CardDescription>
						</CardHeader>
						<CardContent className="space-y-4">
							<div className="grid grid-cols-2 gap-3">
								{[
									{ id: "indigo", name: "SplitGate Indigo", color: "bg-indigo-600" },
									{ id: "emerald", name: "Cyber Emerald", color: "bg-emerald-600" },
									{ id: "violet", name: "Deep Violet", color: "bg-purple-600" },
									{ id: "slate", name: "Enterprise Slate", color: "bg-slate-700" },
								].map((t) => (
									<button
										key={t.id}
										type="button"
										onClick={() => setThemeAccent(t.id)}
										className={`flex items-center gap-3 p-3 rounded-lg border text-left transition-all ${
											themeAccent === t.id ? "border-primary ring-2 ring-primary/20 bg-accent/40" : "hover:bg-muted"
										}`}
									>
										<div className={`h-6 w-6 rounded-full ${t.color}`} />
										<span className="text-xs font-medium">{t.name}</span>
									</button>
								))}
							</div>
						</CardContent>
					</Card>

					<Card className="bg-card/50">
						<CardHeader className="pb-2">
							<CardTitle className="text-sm flex items-center gap-2">
								<Eye className="h-4 w-4 text-primary" />
								Navbar Preview
							</CardTitle>
						</CardHeader>
						<CardContent>
							<div className="flex items-center justify-between rounded-lg border bg-background p-3">
								<div className="flex items-center gap-2.5">
									<div className="flex h-7 w-7 items-center justify-center rounded-md bg-primary text-primary-foreground font-bold text-xs">
										{orgName.charAt(0)}
									</div>
									<span className="font-semibold text-sm">{orgName}</span>
									<span className="text-muted-foreground text-xs">Gateway</span>
								</div>
								<Badge variant="outline" className="text-[10px] bg-emerald-500/10 text-emerald-600">
									Online
								</Badge>
							</div>
						</CardContent>
					</Card>
				</div>
			</div>
		</div>
	);
}