import { defineConfig } from "oxlint";
import effect from "@mpsuesser/oxlint-plugin-effect";

export default defineConfig({
  // Generated TypeDoc site, deployed as-is.
  ignorePatterns: ["docs/**"],
  plugins: ["typescript"],
  jsPlugins: [...effect.configs.recommended.jsPlugins],
  rules: {
    "effect/avoid-non-null-assertion": "error",
    "effect/no-chained-type-assertions": "error",
    "effect/no-module-mocking": "error",
    "typescript/no-explicit-any": "error",
    "typescript/consistent-type-assertions": ["error", { assertionStyle: "never" }],
    "no-unused-vars": [
      "error",
      {
        argsIgnorePattern: "^_",
        varsIgnorePattern: "^_",
        caughtErrorsIgnorePattern: "^_",
        destructuredArrayIgnorePattern: "^_",
      },
    ],
  },
});
