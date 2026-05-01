/**
 * Build-time preset selected via the `VITE_APP_MODE` env var.
 *
 * The same React build powers both the Home Assistant add-on and the standalone
 * Docker UI. A small set of defaults — initial form values, copy strings —
 * differs between the two. CI sets `VITE_APP_MODE` per-variant in
 * `.github/workflows/build.yml` and consumes the produced `frontend/dist` into
 * the matching tarball.
 *
 * Defaults to `docker` so a local `npm run dev` mirrors the standalone build.
 */

export type AppMode = 'ha-addon' | 'docker'

export interface Preset {
  appMode: AppMode
  /** Pre-fills the "Service URL" field when adding a tunnel. */
  defaultServiceUrl: string
  /** Pre-fills the "Label" field when adding a tunnel. */
  defaultLabel: string
  /** Tagline shown next to the HLE logo in the header. */
  productTagline: string
  /** Short copy used in the empty-state and the Add Tunnel CTA. */
  addTunnelCta: string
}

const PRESETS: Record<AppMode, Preset> = {
  'ha-addon': {
    appMode: 'ha-addon',
    defaultServiceUrl: 'http://homeassistant.local.hass.io:8123',
    defaultLabel: 'ha',
    productTagline: 'for Home Assistant',
    addTunnelCta: 'Expose Home Assistant',
  },
  docker: {
    appMode: 'docker',
    defaultServiceUrl: '',
    defaultLabel: '',
    productTagline: 'HomeLab Everywhere',
    addTunnelCta: 'Add Tunnel',
  },
}

const rawMode = import.meta.env.VITE_APP_MODE
const mode: AppMode = rawMode === 'ha-addon' ? 'ha-addon' : 'docker'

export const preset: Preset = PRESETS[mode]
