import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  root: ".",
  build: {
    outDir: "dist",
    rollupOptions: {
      input: {
        content: path.resolve(__dirname, "src/components/content.js"),
        background: path.resolve(__dirname, "src/components/background.js"),
        securityAnalysis: path.resolve(
          __dirname,
          "src/components/securityAnalysis.jsx"
        ),
        popup: path.resolve(__dirname, "src/popup.jsx"),
        popup: path.resolve(__dirname, "popup.html"),
      },
      output: {
        entryFileNames: `assets/[name].js`,
        chunkFileNames: `assets/[name].js`,
        assetFileNames: `assets/[name].[ext]`,
        format: "es", // Use ES modules
        inlineDynamicImports: false,
      },
    },
  },
  define: {
    "process.env.NODE_ENV": JSON.stringify(process.env.NODE_ENV),
  },
});
