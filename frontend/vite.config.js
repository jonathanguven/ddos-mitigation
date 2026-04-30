import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    port: 5173,
    hmr: {
      host: '172.16.64.133',
      clientPort: 5173,
    },
    watch: {
      usePolling: true,
    },
  },
});
