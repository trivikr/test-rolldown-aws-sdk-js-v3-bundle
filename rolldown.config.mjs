import { defineConfig } from "rolldown";

export default defineConfig({
  input: ["./input.js"],
  output: {
    file: "./bundle.js",
    format: "cjs",
    inlineDynamicImports: true,
  },
  logLevel: "debug",
});
