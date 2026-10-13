# infra — a VDS "control panel" on Ansible, without a web UI

[Русский](README.md)

> **First server?** Start with [`START.md`](START.md) — a step-by-step guide from scratch (in Russian).

The engine lives on the server itself (`/opt/infra`) and brings it to the state described in one
file, `/etc/infra/server.yml`: `sudo infra apply`. A server hosts only projects — sites in Docker
Compose: each gets its own network, its own database in a shared Postgres and its own members,
who log in over SSH/SFTP to their project only. SSL, hardening, backups and alerts are set up
for you. Server settings and passwords stay on the server; git holds only the engine.

**Who it is for:** a small team, one or a few VDS, several sites per server (Django, Nuxt, static —
anything in containers), developers working with their project's files, dev and prod on one box.

**Compared to Coolify, Dokploy, CapRover:** no web panel, so no internet-facing endpoint with root
rights; people are separated per project by plain Linux permissions; the result is an ordinary
Ubuntu configuration — remove the engine and the server keeps running. The price is a terminal
and YAML instead of buttons.

## Features

- **Projects:** a folder with code and `compose.yml`, its own Docker network, a database in the shared
  Postgres reachable only from the project network and over an SSH tunnel, Let's Encrypt via Traefik
  labels, memory/CPU limits per project, a prod database copy into `*_dev` with one command.
- **People and access:** Linux accounts per person, SSH/SFTP only into their projects' folders; SSH by
  key from an IP allowlist; an access link opens SSH for your current IP for 24 hours.
- **Security:** only 80/443 open, container ports bound to 127.0.0.1 by default, userns-remap,
  CrowdSec bans in the firewall (never your IPs or your members'), nightly Ubuntu security updates.
- **Backups (restic):** nightly per-project snapshots (files, volumes, DB dump) plus `/etc`; frequent
  snapshots every 1–60 minutes straight to S3; three levels — server, your computer, S3 with Object Lock.
- **Deploys:** push → CI builds an image in ghcr.io → the server picks it up within 15 seconds, runs
  migrations, waits for the health check, rolls back on failure.
- **Monitoring:** a health check every 10 minutes, Telegram alerts only for new and resolved problems,
  a morning summary, an audit log in `/var/log/infra.log`.
- **Management:** one `server.yml` per server, generated passwords, `infra edit` with a diff and
  «Apply?», a terminal menu, weekly `infra update`, `infra upgrade` to a new engine version (only
  versions signed by the author's key — a tag forged on GitHub is refused); your own files next to
  the engine's are left alone.

## Quick start

A fresh VDS with Ubuntu 26.04 (24.04 works too, see Limitations), root login by SSH key:

```bash
ssh root@<IP>
git clone -q https://github.com/mcnickbronx/infra.git /opt/infra
git -C /opt/infra checkout -q v1.7.1          # latest version — CHANGELOG.md
/opt/infra/install.sh
infra init     # server name, Let's Encrypt email, your SSH keys and IPs — then the server is set up
```

A step-by-step guide for beginners (SSH key with a passphrase, the key at your hoster, the hoster's
console as a fallback, a changing IP, S3 with Object Lock, Telegram, domain, all settings) —
[`START.md`](START.md), in Russian.

After that, log in as `ssh admin@<IP>`; root SSH login is closed. Put the restic password
(`restic_password` in `/etc/infra/secrets.yml`) into your password manager right away.

## Menu and commands

No web UI — a terminal menu instead: `sudo infra`. Every item is a regular engine command, shown
above its output; you can type the same by hand.

<img src="docs/menu.png" alt="The sudo infra menu" width="775">

| Command | What it does |
|---|---|
| `sudo infra status` | the server on one screen: projects, backups, alerts, problems; read-only |
| `sudo infra edit [secrets]` | edit `server.yml` (or `secrets.yml`): validate, show the diff, ask «Apply?» |
| `sudo infra apply [--check]` | apply the settings; `--check` only shows the changes |
| `sudo infra update` | updates: Docker, Postgres, Traefik, packages (a new kernel means a reboot) |
| `sudo infra upgrade <version>` | another engine version (a git tag signed by a key in `SIGNERS`), then `apply` |
| `sudo project-compose <project> ps` | `docker compose` of a project, from its folder with its `.env` |
| `sudo project-deploy <project> rollback` | roll back the last autodeploy |
| `sudo project-backup <project>` | a project snapshot now; restore — `project-restore` |
| `sudo infra-access link` | the access link: SSH from your current IP for 24 hours |

## Limitations

- Ubuntu 26.04 LTS. 24.04 works too (our test server runs it) but is not recommended: production
  servers and release checks are on 26.04. For 24.04 add `ubuntu_version: "24.04"` to `server.yml`.
- A fixed stack: Docker Compose, Traefik, shared Postgres (PGDG), restic, CrowdSec; autodeploy pulls from ghcr.io.
- One team per server: `docker_users` are effectively root, and so is any project member once you start
  their project (`project-compose` runs the `compose.yml` they wrote as root). Different teams — different servers.
- **Everything is in Russian:** docs, messages, task names. This page is the only English one.

## Status

I build it for my own servers and run it in production. As is: questions in issues, PRs welcome,
no promises on timing. MIT license.
