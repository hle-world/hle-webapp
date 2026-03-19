/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_APP_MODE: 'ha-addon' | 'docker'
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
