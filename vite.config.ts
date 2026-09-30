import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { viteSingleFile } from "vite-plugin-singlefile";
import path from "node:path";

export default defineConfig(({ mode }) => ({
  base: "./",
  plugins: [react(), ...(mode === "single" ? [viteSingleFile({ removeViteModuleLoader: true })] : [])],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "src"),
      // Keep jsPDF's DOM-capture path out of the bundle: we never call doc.html(),
      // and its embedded image data URIs block artifact sharing.
      html2canvas: path.resolve(__dirname, "src/lib/no-html2canvas.ts"),
      dompurify: path.resolve(__dirname, "src/lib/no-html2canvas.ts"),
    },
  },
  build: {
    outDir: mode === "single" ? "dist-single" : "dist",
    target: "es2020",
    chunkSizeWarningLimit: 3000,
    cssCodeSplit: false,
  },
  test: { environment: "node", include: ["src/**/*.test.ts"] },
}));
