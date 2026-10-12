/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Base URL of the backend API (`backend/app/`). Defaults to
   * `http://localhost:8000` in `src/api/client.ts` when unset, matching
   * `Settings.api_port`'s own default. */
  readonly VITE_API_BASE_URL?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
