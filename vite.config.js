import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Em produção o site fica em /cyberguard-siem-demo/ (GitHub Pages).
export default defineConfig(({ mode }) => ({
  plugins: [react()],
  base: mode === "production" ? "/cyberguard-siem-demo/" : "/",
}));
