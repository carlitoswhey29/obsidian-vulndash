import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["src/**/*.ts", "tests/**/*.ts"],
    languageOptions: {
      parserOptions: {
        project: "./tsconfig.json"
      }
    },
    rules: {
      // Safer TypeScript defaults
      "@typescript-eslint/no-explicit-any": "warn",

      "@typescript-eslint/no-unused-vars": [
        "warn",
        {
          argsIgnorePattern: "^_",
          varsIgnorePattern: "^_"
        }
      ],

      // Allow common Obsidian patterns
      "@typescript-eslint/ban-ts-comment": "off",

      // Encourages better typing
      "@typescript-eslint/explicit-function-return-type": "off",

      // Avoid accidental promises
      "@typescript-eslint/no-floating-promises": "off",

      // Avoid regex issues in Obsidian's markdown parsing / sanitization
      "@/no-control-regex": "off"
    }
  },
  {
    ignores: [
      "node_modules/**",
      "main.js",
      "*.map",
      "dist/**"
    ]
  }
);
