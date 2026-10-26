import type { Plugin } from "vite";
import { handleNodeApi } from "./api";

export function vektorApiPlugin(): Plugin {
  return {
    name: "vektor-api-plugin",
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        if (req.url && (req.url.startsWith("/api/") || req.url === "/api")) {
          handleNodeApi(req, res);
        } else {
          next();
        }
      });
    },
  };
}
