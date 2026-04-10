# CITADEL CONTAINER Baukasten

Dieses Verzeichnis macht CITADEL zum zentralen Container-Orchestrator.

## Struktur

- `REPOS/public.list`: öffentliche Nachbar-Repos
- `REPOS/private.list`: private Nachbar-Repos (in `.gitignore`)
- `REPOS/3rdparty.list`: Direktiven-Referenzen auf `../3RDPARTY`
- `ENV/*.env`: Env-Template-Dateien je Modul
- `build.py`: interaktiver Generator (clone + env + artefakte)
- `generated/`: automatisch erzeugte Artefakte

## List-Format

Alle `*.list` nutzen diese Spalten:

`name|kind|source|target_dir|env_ref|description|default`

- `kind`: `repo` oder `directive`
- `source`: Git-URL (`repo`) oder exakter Pfad zur Direktive (`directive`, z. B. `../../3RDPARTY/<tool>/module.json`)
- `target_dir`: Clone-Ziel im Workspace (bei `directive` `-`)
- `env_ref`: Pfad relativ zu `CITADEL`
- `default`: `y` oder `n` für Vorauswahl

## Nutzung

```bash
cd /home/openclaw/safrano9999/CITADEL/CONTAINER
python3 build.py
```

Der Generator erzeugt in `generated/`:

- `<profile>.env`
- `<profile>.Dockerfile`
- `<profile>.container`
- `<profile>.run.sh` (Podman start)
- `<profile>.docker.sh` (Docker start)
- `<profile>.json`

Zusatz:
- Interaktive Container-Benennung als `citadel-<codename>` (Enter nimmt vorgeschlagenes Adjektiv-Tier-Muster)
- Interaktive Hostname-Abfrage; Name wird in Quadlet (`HostName=`) und Startscripts (`--hostname`) gesetzt
- In der erzeugten `.container` steht unten ein auskommentiertes Paket-Manifest (dnf + repo/directive-Module)
