# WAMP Shell
This project provides a flexible shell access system with both client-server and peer-to-peer modes. 
Clients can connect directly to servers, access servers behind NAT via a central WAMP router, 
or establish peer-to-peer connections using WebRTC handshakes over WAMP. 
It’s designed for routed, secure, and versatile remote shell management.

## Overview

- **`wsh`** – WAMP shell
- **`wcp`** – WAMP file copy
- **`wshd`** – WAMP shell daemon
- **`wsh-keygen`** – key pair generator for authentication

---

## `wsh` – WAMP shell

`wsh` connects to a remote `wshd` server (or peer-to-peer via WebRTC) and provides an end-to-end encrypted shell over WAMP, either interactive or for executing a single command.

### Usage

```bash
wsh [options] <target> [command...]
```

### Examples

```bash
# Run a single command remotely
wsh user@hell ls -la

# via WebRTC (peer-to-peer)
wsh --p2p user@hell ls
```

## `wcp` – Secure File Copy

`wcp` transfers files between local and remote hosts using encrypted WAMP sessions.

### Usage

```bash
wcp <source> <destination>
```

### Examples

```bash
# Copy a file from local to remote
wcp ./file.txt user@hell:/home/user/

# Copy a file from remote to local
wcp user@hell:/home/user/file.txt ./file.txt
```

## `wshd` – Remote Shell Daemon

`wshd` runs on a host and provides shell sessions for incoming `wsh` connections.

### Usage
```bash
# Start the daemon
wshd start
2025/09/17 22:15:13 Procedure registered: wampshell.shell.exec
2025/09/17 22:15:13 Procedure registered: wampshell.shell.upload
2025/09/17 22:15:13 Procedure registered: wampshell.shell.download
2025/09/17 22:15:13 listening on rs://0.0.0.0:8022
```


## `wsh-keygen` – Key Generator

Generates a public/private key pair for use with `wsh` and `wshd`.

### Usage

```bash
# Generate a new key pair
wsh-keygen
```

---

## Quick Start

1. **Generate a key pair**

   ```bash
   wsh-keygen
   ```

2. **Run the daemon on the remote machine**

   ```bash
   wshd start
   ```

3. **Connect from the client**

   ```bash
   wsh  user@hell ip a
   ```

4. **Copy a file**

   ```bash
   wcp ./test.txt user@hell:/tmp/
   ```
