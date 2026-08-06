import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const googleAdkModel = env.GOOGLE_ADK_MODEL || env.VITE_GOOGLE_ADK_MODEL || "gemini-3.5-flash-lite";

  return {
    plugins: [react()],
    define: {
      __GOOGLE_ADK_MODEL__: JSON.stringify(googleAdkModel),
    },
    server: {
      port: 4173,
      allowedHosts: ["safr.zkid.xyz"],
    },
  };
});
