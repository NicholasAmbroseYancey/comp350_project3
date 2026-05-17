[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/zVpLa951)
# DocuVault — Final

---

> Understanding the below will help you answer some of the questions during the tech interview.

## Architecture Overview

DocuVault runs as a 3-container cluster:

- **Coordinator (port 8080)**: Accepts the text-based client protocol (LOGIN/WRITE/READ/...) and is responsible for authentication, request parsing, and replication decisions. For storage operations it forwards requests to the storage nodes using a binary RPC protocol.
- **Storage Node A (internal port 9001)**: Stores the replicated data using the Checkpoint 1 `FileSystem` block store and executes forwarded operations after verifying inter-node authentication (HMAC).
- **Storage Node B (internal port 9002)**: Identical to Storage A; holds the second replica.

The Coordinator maintains persistent TCP connections to each storage node via `StorageClient`, and for each client request it performs one or two storage RPCs depending on the operation.

## Binary Message Protocol

The Coordinator ↔ Storage protocol is a single framed binary message:

- **Magic number**: `0x44564C54` (ASCII `"DVLT"` in big-endian).
- **Frame format**:
  - `magic` (4 bytes, network byte order)
  - `msg_type` (1 byte)
  - `payload_len` (4 bytes, network byte order)
  - `payload` (`payload_len` bytes)
  - `hmac` (32 bytes, HMAC-SHA256)
- **Message types (codes)**:
  - Forwarded ops: `MSG_FORWARD_WRITE=0x01`, `MSG_FORWARD_READ=0x02`, `MSG_FORWARD_DELETE=0x03`, `MSG_FORWARD_LIST=0x04`, `MSG_FORWARD_MKDIR=0x05`, `MSG_FORWARD_STAT=0x06`
  - Acks: `MSG_ACK_OK=0x10`, `MSG_ACK_ERR=0x11`
- **Payload encoding**:
  - String fields are packed as UTF-8 bytes separated by `'\0'` (null byte).
  - Operations that carry file bytes append raw file data after the last `'\0'`.
  - Examples:
    - **WRITE**: `path\0owner\0perms\0<raw bytes>`
    - **READ/DELETE/LIST/STAT**: `path\0`
    - **MKDIR**: `path\0owner\0`
- **HMAC location / coverage**:
  - The HMAC is the final 32 bytes of the frame.
  - It covers the signable region: `msg_type || payload_len || payload` (bytes at offsets 4..(9+N)).

## RPC Design

`StorageClient` is a thin RPC wrapper around one persistent TCP connection to a storage node. It hides:

- **Framing**: building/parsing the `(magic, type, len, payload, hmac)` layout
- **Authentication**: computing/verifying HMAC-SHA256
- **I/O robustness**: looping over partial `send`/`recv` and using socket timeouts

From the Coordinator’s perspective this turns storage operations into normal calls like `storage_a_.read(path, out)` and `storage_b_.write(path, data, user, perms)`. On transport/protocol failure, the RPC returns `AckResult{success=false, error_msg="ERR_STORAGE_FAILURE ..."}`, which the Coordinator converts into client-facing `ERR_` responses.

## Write Locking and Deadlock Recovery

The Coordinator maintains a **per-path write lock** (`WriteLock`) to serialize mutating operations (`WRITE` and `DELETE`) per file path:

- If two concurrent writes target the same path, the second request blocks until the lock is released.
- Each lock records when it was acquired; if the lock is held longer than `LOCK_TIMEOUT_SECONDS`, the Coordinator **forcibly releases** it and logs:
  - `WARN: forced lock release on <path> after timeout`

Trade-off: forced release favors availability over strict mutual exclusion if a handler stalls while holding the lock.

## Replication Strategy

Replication is handled in the Coordinator:

- **WRITE / DELETE**: acquire the per-path lock, forward to **both** storage nodes, wait for both ACKs, release the lock.
- **READ / LIST / STAT / MKDIR**: forwarded to **one** storage node (either replica is acceptable because replicas are intended to be identical).

If one node fails mid-write (RPC failure or `ACK_ERR`), the Coordinator returns `ERR_STORAGE_FAILURE`. This may leave replicas temporarily inconsistent; this simplified implementation does not implement repair/reconciliation.

## Inter-Node Authentication

Both sides share `DOCUVAULT_SECRET` and compute **HMAC-SHA256** over `type || payload_len || payload`. The sender appends the 32-byte tag; the receiver recomputes and compares it.

If a storage node receives a frame with an invalid HMAC, it logs:

- `WARN: rejected unauthenticated message from <ip>`

and responds with `ACK_ERR` (without disconnecting).

## How to Build and Run

```bash
docker-compose up
```
