# HLE Web App

Pre-built tunnel management web UI for bare-metal installs — Proxmox LXC, Raspberry Pi, Linux servers, and more.

This is the same web interface used by [hle-docker](https://github.com/hle-world/hle-docker), packaged as a standalone release tarball that only requires Python 3.11+.

## Quick Install

### Proxmox LXC (one-liner)

```bash
bash -c "$(wget -qO- https://hle.world/scripts/proxmox-install.sh)"
```

### Manual Install

```bash
# Download latest release
curl -sL https://github.com/hle-world/hle-webapp/releases/latest/download/hle-webapp-1.16.0.tar.gz | tar xz
cd hle-webapp-*

# Install Python dependencies
pip install -r requirements.txt

# Run
./run.sh
```

Open `http://localhost:8099` to configure your API key and manage tunnels.

## Login token

The web UI and every `/api` route require a login token. On first start a
random token is generated, printed once in the logs, and stored in
`$HLE_DATA_DIR/ui_token` (mode 0600). Paste it into the login page; the
browser then keeps an HttpOnly session cookie. Scripts can send it as
`Authorization: Bearer <token>` instead.

Lost the token? Read it from `$HLE_DATA_DIR/ui_token`, or delete that file and
restart to generate a new one (this logs out every browser).

By default the server listens on `127.0.0.1` only. Set `HLE_BIND_HOST=0.0.0.0`
to reach it from other machines.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `HLE_API_KEY` | — | API key (can also be set via web UI) |
| `HLE_PORT` | `8099` | Web UI port |
| `HLE_BIND_HOST` | `127.0.0.1` | Interface to listen on (`0.0.0.0` for all) |
| `HLE_UI_TOKEN` | generated | Fixed login token instead of the generated one |
| `HLE_DATA_DIR` | `/var/lib/hle` | Persistent data directory |

## How It Works

Each release contains:
- `backend/` — FastAPI server + pre-built React frontend (in `backend/static/`)
- `run.sh` — Entry point
- `requirements.txt` — Python dependencies (`hle-client`, `fastapi`, `uvicorn`)

No Node.js or build tools needed at runtime.

## Release Chain

- **Client updates**: `hle-client` releases trigger `sync-release.yml` → bumps version in `requirements.txt`
- **UI updates**: `ha-addon` merges trigger `sync-ha-addon.yml` → syncs frontend + backend code
- **Auto-release**: Merges to `main` trigger `auto-release.yml` → creates GitHub release → `build.yml` builds frontend and attaches tarball
