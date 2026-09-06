import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const manifest = JSON.parse(readFileSync(new URL("../demo/manifest.json", import.meta.url), "utf8"));
for (const item of manifest.documents) {
  const bytes = readFileSync(new URL(`../${item.path}`, import.meta.url));
  const actual = createHash("sha256").update(bytes).digest("hex");
  if (actual !== item.sha256) {
    console.error(`${item.path}: expected ${item.sha256}, got ${actual}`);
    process.exit(1);
  }
}
console.log(`Evidence verification passed (${manifest.documents.length} immutable documents).`);
