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

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `HLE_API_KEY` | — | API key (can also be set via web UI) |
| `HLE_PORT` | `8099` | Web UI port |
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
