import { defineConfig } from "vite";

export default defineConfig({
  server: {
    watch: {
      interval: 100,
      usePolling: true,
    },
  },
});
