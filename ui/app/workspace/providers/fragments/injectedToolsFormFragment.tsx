import { MCPClientSelector } from "@/components/entitySelectors/mcpClientSelector";
import { Button } from "@/components/ui/button";
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { getErrorMessage, setProviderFormDirtyState, useAppDispatch, useGetMCPClientsQuery } from "@/lib/store";
import { useUpdateProviderMutation } from "@/lib/store/apis/providersApi";
import type { ModelProvider } from "@/lib/types/config";
import { injectedWebSearchFormSchema, type InjectedWebSearchFormSchema } from "@/lib/types/schemas";
import { RbacOperation, RbacResource, useRbac } from "@enterprise/lib";
import { zodResolver } from "@hookform/resolvers/zod";
import { useEffect, useMemo } from "react";
import { useForm, type Resolver } from "react-hook-form";
import { toast } from "sonner";
import { buildProviderUpdatePayload } from "../views/utils";

interface InjectedToolsFormFragmentProps {
	provider: ModelProvider;
}

// The provider stores the MCP client by name, while the client picker works by id.
function useSavedClientId(clientName: string): string {
	const { data } = useGetMCPClientsQuery({ search: clientName, limit: 50 }, { skip: clientName === "" });
	return useMemo(() => data?.clients?.find((c) => c.config.name === clientName)?.config.client_id ?? "", [data, clientName]);
}

export function InjectedToolsFormFragment({ provider }: InjectedToolsFormFragmentProps) {
	const dispatch = useAppDispatch();
	const hasUpdateProviderAccess = useRbac(RbacResource.ModelProvider, RbacOperation.Update);
	const [updateProvider, { isLoading: isUpdatingProvider }] = useUpdateProviderMutation();

	const saved = provider.injected_tools?.web_search;
	const savedClientName = saved?.mcp_client_name ?? "";
	const savedToolName = saved?.tool_name ?? "";
	const savedClientId = useSavedClientId(savedClientName);

	const form = useForm<InjectedWebSearchFormSchema, any, InjectedWebSearchFormSchema>({
		resolver: zodResolver(injectedWebSearchFormSchema) as Resolver<InjectedWebSearchFormSchema, any, InjectedWebSearchFormSchema>,
		mode: "onChange",
		reValidateMode: "onChange",
		defaultValues: { mcp_client_id: savedClientId, mcp_client_name: savedClientName, tool_name: savedToolName },
	});

	useEffect(() => {
		dispatch(setProviderFormDirtyState(form.formState.isDirty));
	}, [form.formState.isDirty, dispatch]);

	useEffect(() => {
		form.reset({ mcp_client_id: savedClientId, mcp_client_name: savedClientName, tool_name: savedToolName });
	}, [form, provider.name, savedClientId, savedClientName, savedToolName]);

	const clientId = form.watch("mcp_client_id");
	const { data: selectedClientData } = useGetMCPClientsQuery({ server: clientId, limit: 1 }, { skip: clientId === "" });
	const selectedClient = selectedClientData?.clients?.[0];
	const tools = selectedClient?.tools ?? [];

	// The picker reports only the id; the provider config stores the name.
	useEffect(() => {
		if (
			selectedClient &&
			selectedClient.config.client_id === clientId &&
			form.getValues("mcp_client_name") !== selectedClient.config.name
		) {
			form.setValue("mcp_client_name", selectedClient.config.name, { shouldDirty: true, shouldValidate: true });
		}
	}, [selectedClient, clientId, form]);

	const save = (data: InjectedWebSearchFormSchema | null) => {
		const injectedTools =
			data && data.mcp_client_name ? { web_search: { mcp_client_name: data.mcp_client_name, tool_name: data.tool_name } } : null;
		updateProvider(buildProviderUpdatePayload(provider, { injected_tools: injectedTools }))
			.unwrap()
			.then(() => {
				toast.success(injectedTools ? "Web search tool updated" : "Web search tool removed");
				form.reset(data ?? { mcp_client_id: "", mcp_client_name: "", tool_name: "" });
			})
			.catch((err) => {
				toast.error("Failed to update web search tool", { description: getErrorMessage(err) });
			});
	};

	return (
		<Form {...form}>
			<form onSubmit={form.handleSubmit(save)} className="space-y-6 px-4 md:px-6" data-testid="provider-config-web-search-content">
				<p className="text-muted-foreground text-xs">
					Pick an MCP tool to serve as web search for every chat and responses request to this provider. Bifrost adds the tool to each
					request, replaces any native web search the client sends, runs the tool itself when the model calls it, and returns only the final
					answer.
				</p>
				<FormField
					control={form.control}
					name="mcp_client_id"
					render={({ field }) => (
						<FormItem>
							<FormLabel>MCP server</FormLabel>
							<FormControl>
								<div data-testid="provider-web-search-client-select">
									<MCPClientSelector
										value={field.value}
										onChange={(value) => {
											field.onChange(value);
											form.setValue("mcp_client_name", "", { shouldDirty: true });
											form.setValue("tool_name", "", { shouldDirty: true, shouldValidate: true });
										}}
										disabled={!hasUpdateProviderAccess}
										fallbackOption={savedClientId ? { value: savedClientId, label: savedClientName } : null}
									/>
								</div>
							</FormControl>
							<FormMessage />
						</FormItem>
					)}
				/>
				<FormField
					control={form.control}
					name="tool_name"
					render={({ field }) => (
						<FormItem>
							<FormLabel>Tool</FormLabel>
							<Select value={field.value} onValueChange={field.onChange} disabled={!hasUpdateProviderAccess || clientId === ""}>
								<FormControl>
									<SelectTrigger className="w-full" data-testid="provider-web-search-tool-select">
										<SelectValue placeholder={clientId === "" ? "Pick an MCP server first" : "Pick a tool"} />
									</SelectTrigger>
								</FormControl>
								<SelectContent>
									{tools.map((tool) => (
										<SelectItem key={tool.name} value={tool.name} data-testid={`provider-web-search-tool-option-${tool.name}`}>
											{tool.name}
										</SelectItem>
									))}
								</SelectContent>
							</Select>
							<FormMessage />
						</FormItem>
					)}
				/>

				<div className="flex justify-end space-x-2 pb-6">
					{saved && (
						<Button
							type="button"
							variant="outline"
							data-testid="provider-web-search-remove-btn"
							disabled={!hasUpdateProviderAccess || isUpdatingProvider}
							onClick={() => save(null)}
						>
							Remove
						</Button>
					)}
					<Button
						type="submit"
						data-testid="provider-web-search-save-btn"
						disabled={!form.formState.isDirty || !form.formState.isValid || !hasUpdateProviderAccess || isUpdatingProvider}
						isLoading={isUpdatingProvider}
					>
						Save Web Search Tool
					</Button>
				</div>
			</form>
		</Form>
	);
}