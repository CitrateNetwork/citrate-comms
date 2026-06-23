import js from "@eslint/js";
import globals from "globals";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: [".next/**", "node_modules/**", "src/lib/db/migrations/**", "coverage/**"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    rules: {
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_", varsIgnorePattern: "^_" }],
    },
  },
  {
    // Node scripts (migrations, tooling) run in Node, not the browser/edge runtime.
    files: ["scripts/**/*.mjs", "*.config.{ts,mjs}", "drizzle.config.ts"],
    languageOptions: { globals: { ...globals.node } },
  },
);
