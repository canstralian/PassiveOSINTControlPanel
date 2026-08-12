/**
 * Mock tool gateway.
 *
 * The gateway is the single chokepoint for tool execution. Real adapters
 * are NOT introduced until the safety chain, audit chain, approval flow,
 * and tests are all green. Tools registered here are simulated and
 * deterministic.
 */
export type ToolInvocation = {
  toolId: string;
  input: unknown;
  // The investigationId / actionId / approval reference are passed through
  // by the chain and recorded here for tool-side audit hooks.
  context: {
    investigationId: string;
    actionId: string;
  };
};

export type ToolResultEnvelope = {
  ok: boolean;
  toolId: string;
  output?: unknown;
  errorMessage?: string;
  // Latency reported by the mock gateway, used to update budgets.
  latencyMs: number;
};

export type ToolHandler = (invocation: ToolInvocation) => Promise<ToolResultEnvelope>;

export class ToolGateway {
  private readonly handlers = new Map<string, ToolHandler>();

  register(toolId: string, handler: ToolHandler): void {
    if (this.handlers.has(toolId)) {
      throw new Error(`Tool already registered: ${toolId}`);
    }
    this.handlers.set(toolId, handler);
  }

  async invoke(invocation: ToolInvocation): Promise<ToolResultEnvelope> {
    const handler = this.handlers.get(invocation.toolId);
    if (!handler) {
      return {
        ok: false,
        toolId: invocation.toolId,
        errorMessage: `unknown tool: ${invocation.toolId}`,
        latencyMs: 0,
      };
    }
    const start = Date.now();
    try {
      return await handler(invocation);
    } catch (err) {
      // Normalize handler exceptions into a failure envelope so the chain
      // can keep deterministic stage handling.
      return {
        ok: false,
        toolId: invocation.toolId,
        errorMessage: err instanceof Error ? err.message : String(err),
        latencyMs: Date.now() - start,
      };
    }
  }

  has(toolId: string): boolean {
    return this.handlers.has(toolId);
  }
}
