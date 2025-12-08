import { defineConfig } from "rolldown";

export default defineConfig({
  input: ["./input.js"],
  output: {
    file: "./bundle.js",
    inlineDynamicImports: true,
    minify: true,
    format: "esm",
  },
});
