// worker.js importa due PDF come moduli (le `rules` di wrangler li trasformano)
// e due JSON senza attributo di import: Node non sa farlo da solo. Qui i PDF
// diventano un Uint8Array vuoto (i test non rendono il certificato) e i JSON
// vengono letti dal disco. worker.js NON viene modificato.
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

export async function load(url, context, nextLoad) {
  if (url.endsWith(".pdf")) {
    return {
      format: "module",
      shortCircuit: true,
      source: "export default new Uint8Array(0);",
    };
  }
  if (url.endsWith(".json")) {
    const text = await readFile(fileURLToPath(url), "utf8");
    return {
      format: "module",
      shortCircuit: true,
      source: `export default ${text};`,
    };
  }
  return nextLoad(url, context);
}
