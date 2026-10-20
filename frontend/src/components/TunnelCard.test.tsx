import { describe, expect, it } from 'vitest'
import { renderToStaticMarkup } from 'react-dom/server'
import { TunnelCard } from './TunnelCard'
import type { TunnelStatus } from '../api/client'

// The docs screenshot pipeline masks install-specific text via the
// `data-sensitive` attribute, so the tunnel list must keep marking the label,
// public URL and service URL.
const tunnel: TunnelStatus = {
  id: 't-1',
  service_url: 'http://192.168.1.50:8096',
  label: 'jellyfin',
  name: 'Jellyfin',
  auth_mode: 'sso',
  verify_ssl: false,
  websocket_enabled: true,
  api_key_set: false,
  api_key_masked: null,
  has_upstream_basic_auth: false,
  upstream_basic_auth_user: null,
  forward_host: false,
  response_timeout: null,
  subdomain: 'jellyfin-abc123',
  public_url: 'https://jellyfin-abc123.hle.world',
  zone_domain: null,
  webhook_path: null,
  server_tunnel_id: null,
  tier: null,
  state: 'CONNECTED',
  error: null,
  pid: null,
}

describe('TunnelCard screenshot masking', () => {
  it('marks the label, public URL and service URL with data-sensitive', () => {
    const html = renderToStaticMarkup(<TunnelCard tunnel={tunnel} onRefresh={() => {}} />)

    expect(html).toMatch(/<span[^>]*data-sensitive=""[^>]*>Jellyfin<\/span>/)
    expect(html).toMatch(/<a[^>]*data-sensitive=""[^>]*>https:\/\/jellyfin-abc123\.hle\.world<\/a>/)
    expect(html).toMatch(/<span[^>]*data-sensitive=""[^>]*>http:\/\/192\.168\.1\.50:8096<\/span>/)
  })
})
