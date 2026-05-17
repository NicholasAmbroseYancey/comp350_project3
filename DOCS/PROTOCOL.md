# DocuVault Protocol and Architecture

## Q&A (questions with answers)

### 1) Describe your 3-node architecture at a high level. How do the Coordinator and Storage nodes interact? What role does each container play?
Answer:
- Topology: a 3-node deployment with one `Coordinator` and two `Storage` nodes (replicas).
- The `Coordinator` accepts client requests, owns metadata and per-file locks, composes and signs binary frames, forwards operations to both Storage nodes, validates replies, manages replication/repair, and exposes the client API.
- Each `Storage` node receives frames from the Coordinator, verifies HMAC, performs local FS ops (atomic write via tmp+fsync+rename), and replies with `MSG_ACK_OK` or `MSG_ACK_ERR`.
- Containers: the Coordinator container runs the coordinator service and lock manager; each Storage container runs the storage service and persists files to its local volume.

### 2) What is your magic number?
Answer: `0x44564C54` (ASCII "DVLT").

### 3) What message types did you define and what are their codes?
Answer:
- Forward (Coordinator → Storage):
  - `MSG_FORWARD_WRITE = 0x01` — write/create file
  - `MSG_FORWARD_READ  = 0x02` — read file
  - `MSG_FORWARD_DELETE= 0x03` — delete file
  - `MSG_FORWARD_LIST  = 0x04` — list directory
  - `MSG_FORWARD_MKDIR = 0x05` — create directory
  - `MSG_FORWARD_STAT  = 0x06` — stat metadata
- Ack/Response (Storage → Coordinator):
  - `MSG_ACK_OK  = 0x10` — success
  - `MSG_ACK_ERR = 0x11` — error (payload contains code+message)

### 4) How is the payload structured for each message type?
Answer: (summary — see detailed payload layouts below)
- General encodings: strings are `uint32 length + UTF-8 bytes`; file data blobs use `uint64 length + bytes`; integers are big-endian fixed-width; lists are `uint32 count + entries`.
- `MSG_FORWARD_WRITE`: path (len+str), owner (len+str), perms (4B uint32), mtime (8B int64), data_len (8B uint64), data (bytes).
- `MSG_FORWARD_READ`: path (len+str), offset (8B), length (8B). Response contains metadata + data_len (8B) + data.
- `MSG_FORWARD_DELETE`: path (len+str).
- `MSG_FORWARD_LIST`: path (len+str). Response: count (4B) + entries (type 1B + name len+bytes + metadata).
- `MSG_FORWARD_MKDIR`: path (len+str), perms (4B).
- `MSG_FORWARD_STAT`: path (len+str). Response: is_dir (1B) + size (8B) + owner (len+str) + perms (4B) + mtime (8B).

### 5) Where does the HMAC tag sit in the frame, and what bytes does it cover?
Answer:
- Frame layout: `magic (4B) || msg_type (1B) || payload_len (4B) || payload (N bytes) || hmac (32B)`.
- The HMAC (32 bytes, HMAC-SHA256) is appended at the end of the frame.
- The HMAC covers `msg_type || payload_len || payload` (i.e., everything after the 4-byte magic through the end of payload).

### 6) Describe your `StorageClient` class. How does it abstract the binary protocol so the Coordinator's logic reads like regular function calls? What does error handling look like from the Coordinator's perspective?
Answer:
- `StorageClient` exposes call-style methods: `write()`, `read()`, `remove()`, `list()`, `mkdir()`, `stat()` returning typed results or throwing typed exceptions.
- Internals: builds frames, computes/appends HMAC, sends frames over socket, waits for response, verifies response HMAC, parses payload into structs, and translates errors into exceptions (`NetworkError`, `InvalidHMACError`, `StorageErr(code,msg)`, `TimeoutError`).
- Coordinator uses these calls synchronously/asynchronously and treats exceptions uniformly: log, increment node-failure counters, retry bounded times for transient errors, mark node degraded/offline on persistent or auth failures, and enqueue repairs as needed.

### 7) Explain how your per-file write locking works. What happens when two concurrent writes target the same file? How does the timeout-based deadlock recovery mechanism work? What trade-offs did you make?
Answer:
- Lock model: Coordinator maintains an in-memory lock table keyed by normalized path; locks store owner request id, acquired_at, and lease TTL.
- Concurrency: the Coordinator serializes writes — the second concurrent writer is either queued or given a `BUSY` response depending on policy; only the lock holder may forward writes to storage.
- Timeout/lease recovery: locks have TTL (e.g., 30s). If TTL expires, Coordinator treats the lock as expired, checks for partial writes (temp files), attempts rollback or repair, forces lock release, and proceeds.
- Trade-offs: lease TTLs avoid permanent deadlocks but risk aborting slow legitimate writers; single-coordinator simplifies locking but is a single coordination point.

### 8) Describe how writes are replicated to both storage nodes. What happens if one node fails mid-write? How do you handle the inconsistency?
Answer:
- Replication: Coordinator sends write frames to both storage nodes (prefer parallel) and waits for ACKs within a timeout.
- If one node fails mid-write: if one ACK and one timeout/ERR, the Coordinator marks the node degraded, returns error/partial-failure per policy, and enqueues a background repair to copy from the healthy node when it recovers.
- If ACK is sent only after durability (fsync+rename), surviving node is authoritative for repairs; background worker copies file to recovered node using checksums/mtime to resolve.
- Trade-offs: eventual consistency and repair-based recovery instead of strong consensus; simpler implementation but possible transient inconsistency.

### 9) How do you compute and verify the HMAC tag? What happens when a storage node receives a message with an invalid HMAC?
Answer:
- Compute: `HMAC = HMAC_SHA256(shared_key, msg_type || payload_len || payload)`; append 32-byte tag.
- Verify: storage recomputes HMAC over same bytes and compares using constant-time compare.
- Invalid HMAC handling: storage drops the request, logs the event, and either replies with `MSG_ACK_ERR` with `ERR_INVALID_HMAC` or closes the connection per policy. Coordinator treats invalid-HMAC responses as severe auth/comm errors, marks node suspect, and does not accept the response.



## Architecture Overview
- Topology: 3-node deployment — one Coordinator and two Storage nodes (Storage A, Storage B).
- Coordinator: accepts client requests, manages metadata and per-file locks, forwards binary protocol messages to storage nodes, handles replication and repair.
- Storage nodes: accept Coordinator-forwarded binary frames, perform local filesystem operations (atomic write via temp+fsync+rename, read, delete, list, mkdir, stat), and reply with ACK frames.
- Containers:
  - Coordinator container: runs the coordinator service and lock manager.
  - Storage containers: run storage node services and persist files to local volumes.
- Interaction flow: Client → Coordinator (API) → Coordinator composes binary frames → sends to both Storage nodes → Storage nodes perform ops and respond → Coordinator verifies responses and returns result to client or enqueues repair.

## Protocol Summary
- Magic number: `0x44564C54` (ASCII "DVLT").
- Message types and codes:
  - Forward (Coordinator → Storage)
    - `MSG_FORWARD_WRITE = 0x01` — Write/create a file
    - `MSG_FORWARD_READ  = 0x02` — Read a file
    - `MSG_FORWARD_DELETE= 0x03` — Delete a file
    - `MSG_FORWARD_LIST  = 0x04` — List directory contents
    - `MSG_FORWARD_MKDIR = 0x05` — Create a directory
    - `MSG_FORWARD_STAT  = 0x06` — Get file/directory metadata
  - Ack/Response (Storage → Coordinator)
    - `MSG_ACK_OK  = 0x10` — Success
    - `MSG_ACK_ERR = 0x11` — Error (payload carries code/message)

### Frame format (network / big-endian)
```
magic (4 bytes)
msg_type (1 byte)
payload_len (4 bytes, uint32)
payload (payload_len bytes)
hmac (32 bytes, HMAC-SHA256)
```

### HMAC placement & coverage
- HMAC is appended at the end of the frame (final 32 bytes).
- The HMAC covers the bytes: `msg_type || payload_len || payload` (i.e., everything after the 4-byte magic through end of payload).

## Encoding Rules
- Endianness: network (big-endian).
- Strings: 4-byte uint32 length followed by UTF-8 bytes. (len=0 allowed.)
- Binary blobs (file data): 8-byte uint64 length followed by raw bytes.
- Integers: fixed-width big-endian (e.g., perms as 4-byte uint32; sizes as 8-byte uint64; times as 8-byte int64 epoch ms/seconds).
- Booleans/flags: 1 byte (0/1).
- Lists: 4-byte count followed by repeated entries.

## Per-Message Payload Layouts

- MSG_FORWARD_WRITE (0x01)
  - path: (4B len + bytes)
  - owner: (4B len + bytes)
  - perms: (4B uint32)
  - mtime: (8B int64) — optional
  - data_len: (8B uint64)
  - data: (data_len bytes)
  - Storage behavior: write to temp file, fsync, atomic rename, set owner/perms/mtime, then reply `MSG_ACK_OK`.

- MSG_FORWARD_READ (0x02)
  - path: (4B len + bytes)
  - offset: (8B uint64)
  - length: (8B uint64) — 0 means read to EOF
  - Storage `MSG_ACK_OK` payload: metadata + data_len(8B) + data
  - On error: `MSG_ACK_ERR` with error code + message.

- MSG_FORWARD_DELETE (0x03)
  - path: (4B len + bytes)

- MSG_FORWARD_LIST (0x04)
  - path: (4B len + bytes)
  - `MSG_ACK_OK` payload: count(4B) + repeated entries: type(1B) + name(4B len + bytes) + metadata(size 8B + perms 4B + owner len+str).

- MSG_FORWARD_MKDIR (0x05)
  - path: (4B len + bytes)
  - perms: (4B)

- MSG_FORWARD_STAT (0x06)
  - path: (4B len + bytes)
  - `MSG_ACK_OK` payload: is_dir(1B) + size(8B) + owner(4B+bytes) + perms(4B) + mtime(8B)

Error frames (`MSG_ACK_ERR`) carry an error code (4B) + message (4B len + bytes).

## HMAC Key and Verification
- Shared secret key is configured on Coordinator and each Storage node at startup.
- Algorithm: HMAC-SHA256, tag length 32 bytes.
- Compute over: `msg_type || payload_len || payload`.
- Use constant-time comparison for verification.
- Optional anti-replay: include timestamp or monotonic counter inside payload and verify freshness.

## StorageClient (abstraction)
- Purpose: hide binary protocol so Coordinator code looks like function calls.
- Typical API (synchronous or async):
  - `write(path, owner, perms, data, timeout) -> Status` or throws `StorageError`
  - `read(path, offset=0, length=0, timeout) -> ReadResult`
  - `remove(path, timeout) -> Status`
  - `list(path, timeout) -> ListResult`
  - `mkdir(path, perms, timeout) -> Status`
  - `stat(path, timeout) -> StatResult`
- Responsibilities:
  - Build frames, compute and append HMAC, send and wait for response.
  - Validate response HMAC, parse payloads into typed results.
  - Implement socket timeouts, small retries on transient network errors.
- Error surface to Coordinator: typed exceptions such as `NetworkError`, `InvalidHMACError`, `StorageErr(code,msg)`, `TimeoutError`.

## Coordinator Error Handling Policy
- Writes: send to both storage nodes (parallel), wait for both ACKs within timeout.
  - Both OK → success.
  - One OK, one ERR/timeout → mark node degraded, return error or partial-failure per policy, enqueue background repair.
  - Both fail → return error.
- Reads: prefer healthy node; failover to replica if needed.
- Retries: bounded retries for transient network failures; never retry `InvalidHMACError`.

## Per-file Write Locking and Deadlock Recovery
- Lock table: Coordinator keeps an in-memory lock table keyed by normalized path. Each lock stores owner request id, acquired_at timestamp, and lease TTL.
- Concurrency: second concurrent writer is queued or receives `BUSY` depending on policy; Coordinator serializes writes to same path.
- Lease-based timeout recovery:
  - Each lock has TTL (e.g., 30s). If TTL expires, Coordinator treats the lock as expired, attempts recovery (check for temp files or partial writes), rolls back or repairs as appropriate, then forcibly releases lock.
  - Trade-offs: avoids permanent deadlock but risks aborting slow legitimate writers; TTL must be tuned.

## Replication and Mid-write Failure Handling
- Replication model: Coordinator sends writes to both storage nodes (preferred: parallel) and waits for ACKs.
- If one node fails mid-write:
  - If one ACK and one timeout: operation is degraded. Coordinator marks failing node degraded, returns error/partial-failure per policy, and enqueues background repair to copy from healthy node when it recovers.
  - If ACK implies durability (storage ACKs only after fsync+rename), surviving node is authoritative for repair.
- Repair: background worker copies missing files from healthy node to recovered node, using checksums/mtime to choose authoritative copy.
- Trade-offs: simpler design without consensus; uses eventual repair rather than strong synchronous consistency.

## HMAC Computation & Invalid Tag Handling
- Compute: `HMAC = HMAC_SHA256(shared_key, msg_type || payload_len || payload)`; append 32-byte tag.
- Verify: storage recomputes and compares using constant-time compare.
- On invalid HMAC at storage: drop request, log event, reply `MSG_ACK_ERR` with `ERR_INVALID_HMAC` or close connection depending on policy.
- Coordinator on invalid HMAC in response: treat as severe communication/auth error, mark node suspect/offline, do not accept response.

---
If you want, I can add C++ `struct` definitions and serialization helpers for these frames and payloads (for `StorageClient` and storage node). I can also move this file into `DOCS/PROTOCOL.md` if you prefer that location.
