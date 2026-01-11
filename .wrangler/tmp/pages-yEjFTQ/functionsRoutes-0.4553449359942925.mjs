import { onRequestOptions as __api_intake_ts_onRequestOptions } from "/Volumes/MacMiniOps/Static Sites Workspace/getyours-site/functions/api/intake.ts"
import { onRequestPost as __api_intake_ts_onRequestPost } from "/Volumes/MacMiniOps/Static Sites Workspace/getyours-site/functions/api/intake.ts"

export const routes = [
    {
      routePath: "/api/intake",
      mountPath: "/api",
      method: "OPTIONS",
      middlewares: [],
      modules: [__api_intake_ts_onRequestOptions],
    },
  {
      routePath: "/api/intake",
      mountPath: "/api",
      method: "POST",
      middlewares: [],
      modules: [__api_intake_ts_onRequestPost],
    },
  ]