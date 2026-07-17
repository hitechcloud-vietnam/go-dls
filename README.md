# go-dls

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/in-jun/go-dls)](https://goreportcard.com/report/github.com/in-jun/go-dls)

Local NVIDIA vGPU license server. Runs fully offline — no internet connection or purchased license required.

## Driver Compatibility

| Driver Version | Support |
|---|---|
| 17.x (535.x) | go-dls only |
| 18.x (570.x) | go-dls + [gridd-unlock-patcher](https://git.collinwebdesigns.de/oscar.krause/gridd-unlock-patcher) |

## Usage

### 1. Run the license server

Run on any host reachable from your guest VM (Proxmox host, separate VM, or inside the guest itself).

```bash
docker run -d \
  -e DLS_URL=192.168.1.x \
  -p 443:443 \
  -v dls-cert:/app/cert \
  -v dls-db:/app/db \
  injundev/go-dls
```

Set `DLS_URL` to the IP or hostname that your guest VM can reach.

To run inside the guest VM itself:

```bash
docker run -d \
  -e DLS_URL=127.0.0.1 \
  -p 443:443 \
  -v dls-cert:/app/cert \
  -v dls-db:/app/db \
  injundev/go-dls
```

### 2. Install the client token

Run inside the guest VM after installing the vGPU guest driver.

```bash
mkdir -p /etc/nvidia/ClientConfigToken
curl -sk https://<DLS_URL>/-/client-token \
  -o /etc/nvidia/ClientConfigToken/client_configuration_token.tok
systemctl restart nvidia-gridd
```

### 3. Verify

```bash
nvidia-smi -q | grep "License"
```

`Licensed` confirms the license is active.

## Management UI

Visit `https://<DLS_URL>/-/manage` to view connected VMs and active leases.

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `DLS_URL` | `localhost` | IP or hostname reachable from guest VMs (embedded in .tok) |
| `DLS_PORT` | `443` | HTTPS listen port |
| `CERT_DIR` | `/app/cert` | TLS certificate directory |
| `DB_DSN` | `/app/db/db.sqlite` | SQLite database path |
| `LEASE_EXPIRE_DAYS` | `90` | Lease validity in days |
| `LEASE_RENEWAL_PERIOD` | `0.15` | Renewal threshold (fraction of lease duration remaining) |
| `TOKEN_EXPIRE_DAYS` | `1` | Access token validity in days |

## Build

```bash
docker build -t go-dls .
```
