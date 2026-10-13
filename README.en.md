# infra — a VDS "control panel" on Ansible, without a web UI

[Русский](README.md)

The engine lives on the server itself (`/opt/infra`) and brings it to the state described in one
file, `/etc/infra/server.yml`: `sudo infra apply`. A server hosts only projects — sites in Docker
Compose: each gets its own network, its own database in a shared Postgres and its own members,
who log in over SSH/SFTP to their project only. SSL, hardening, backups and alerts are set up
for you. Server settings and passwords stay on the server; git holds only the engine.

**Who it is for:** a small team, one or a few VDS, several sites per server (Django, Nuxt, static —
anything in containers), developers working with their project's files, dev and prod on one box.

**What you get:**

- only ports 80 and 443 are open; SSH by key and from an IP allowlist, with a secret link that
  opens SSH for your current IP for 24 hours; CrowdSec bans attackers in the firewall;
- root in a container is not root on the host (userns-remap); a network and memory/CPU limits per project;
- Let's Encrypt via Traefik: a site is a `compose.yml` with labels;
- restic backups on three levels — on the server, on your computer and in S3 with Object Lock;
  the server cannot delete any copy; nightly and, if needed, every N minutes;
- autodeploy: push → CI builds an image → the server pulls it, rolls back on failure;
- Telegram alerts only for new and resolved problems, plus a morning summary;
- an audit log in `/var/log/infra.log` and a terminal menu, `sudo infra`.

**Compared to Coolify, Dokploy, CapRover:** no web panel, so no internet-facing endpoint with root
rights; people are separated per project by plain Linux permissions; the result is an ordinary
Ubuntu configuration — remove the engine and the server keeps running. The price is a terminal
and YAML instead of buttons.

## Quick start

A fresh VDS with Ubuntu 26.04, root login by SSH key:

```bash
ssh root@<IP>
git clone -q https://github.com/mcnickbronx/infra.git /opt/infra
git -C /opt/infra checkout -q v1.7.0          # latest version — CHANGELOG.md
/opt/infra/install.sh
infra init     # server name, Let's Encrypt email, your SSH keys and IPs — then the server is set up
```

After that, log in as `ssh admin@<IP>`; root SSH login is closed. Put the restic password
(`restic_password` in `/etc/infra/secrets.yml`) into your password manager right away.

## Limitations

- Ubuntu 26.04 LTS only.
- A fixed stack: Docker Compose, Traefik, shared Postgres (PGDG), restic, CrowdSec; autodeploy pulls from ghcr.io.
- One team per server: `docker_users` are effectively root. Different teams — different servers.
- **Everything is in Russian:** docs, messages, task names. This page is the only English one.

## Status

I build it for my own servers and run it in production. As is: questions in issues, PRs welcome,
no promises on timing. MIT license.
