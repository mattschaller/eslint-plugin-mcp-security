import mcpSecurity from "../dist/index.js";
import * as parser from "@typescript-eslint/parser";

export default [
  {
    files: ["**/*.ts"],
    languageOptions: { parser },
  },
  mcpSecurity.configs.recommended,
];
