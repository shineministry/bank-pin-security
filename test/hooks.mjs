/* Lets plain Node resolve the Workers-only `cloudflare:workers` builtin.
 * Registered from vault.test.mjs via node:module register() before worker.js
 * is imported, so the suite still runs with `node test/vault.test.mjs`.
 */
const SHIM = `
export class DurableObject {
  constructor(ctx, env) {
    this.ctx = ctx;
    this.env = env;
  }
}
`;

export async function resolve(specifier, context, nextResolve) {
  if (specifier === "cloudflare:workers") {
    return {
      url: "data:text/javascript," + encodeURIComponent(SHIM),
      shortCircuit: true,
    };
  }
  return nextResolve(specifier, context);
}
