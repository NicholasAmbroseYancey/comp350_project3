**DocuVault — API & Function Summary**

- **Purpose:** Quick reference for major files, functions, and their behaviors.

**Top-level / Docker**
- **docker-compose.yml:** Defines three services: `coordinator`, `storage-a`, `storage-b`. Coordinator exposed on 8080, storage nodes run internal ports (9001/9002), share `DOCUVAULT_SECRET`, and mount local `./data/*` volumes on `/data` inside containers. Uses `docuvault-net` bridge network.
- **Dockerfile.coordinator:** Installs build deps, copies `src/` and `data/`, compiles `docuvault_coordinator` from `coordinator.cpp`, `storage_client.cpp`, `auth.cpp`, exposes port 8080.
- **Dockerfile.storage:** Installs build deps, copies `src/`, compiles `docuvault_storage` from `storage_node.cpp`, `storage_client.cpp`, `fs.cpp`, creates default `/data/store`, exposes port 9001 (overrideable).

**Wire Protocol** — `src/protocol.h`
- `PROTO_MAGIC`, `MessageType`, `HMAC_SIZE`, `MessageFrame`: wire-format constants/structs.
- `packFields(fields, trailing_data)`: pack NUL-separated string fields + optional trailing binary data.
- `unpackFields(payload, count, fields, data_offset)`: extract `count` fields and return trailing data offset.

**Authentication** — `src/auth.h`, `src/auth.cpp`
- `AuthManager::AuthManager(user_file_path)`: loads users file into memory.
- `AuthManager::loadUsers(path)`: parse `username:sha256_hex` lines.
- `AuthManager::authenticate(username, password)`: hash password and compare.
- `AuthManager::userExists(username)`: check presence.
- `AuthManager::hashPassword(input)`: SHA-256 hex digest helper.

**File System (block store)** — `src/fs.h`, `src/fs.cpp`
- Constants: `BLOCK_SIZE` (4096), `MAX_BLOCKS` (1024), `BUFFER_CAP` (4096).
- `FileMetadata`: metadata per file/dir (name, path, owner, size, perms, timestamps, is_dir, blocks).

WriteBuffer class:
- `append(data,len)`: append up to `BUFFER_CAP` bytes, return appended size.
- `clear()`: clear buffer and target path.
- `isFull()`, `hasData()`, `size()`, `data()`, `setTargetPath(p)`, `targetPath()` — accessors.

FileSystem key methods:
- `FileSystem::FileSystem(base_path)`: ctor, calls `init()`.
- `init()`: create directories, load index or create root entry.
- `saveIndex()` / `loadIndex()`: persist/load `index.dat` and rebuild `block_bitmap_`.
- `createDirectory(path, owner)`: add directory and save index.
- `listDirectory(path)`: list immediate children of a directory.
- `writeFile(path, data, owner)`: main write logic —
  - If existing file: calls `freeBlocks(old.blocks)` immediately and clears old block list.
  - Updates `size` and timestamps in `index_` and calls `saveIndex()`.
  - Buffers data in `WriteBuffer` (up to `BUFFER_CAP`) and triggers `flushBuffer()` if buffer becomes full.
  - Note: if `write_buffer_` already has data for a different path, it is flushed; if same path, existing buffer is cleared (new write overwrites buffered content).
- `flushBuffer()`: when buffer has data — computes `blocks_needed`, calls `allocateBlocks(blocks_needed)` which marks bitmap bits true, writes each block via `writeBlock(block_id, ...)`, appends block IDs to `index_[path].blocks`, updates `modified`, clears buffer, and `saveIndex()`.
- `readFile(path, data_out)`: if buffer has data for this path, `flushBuffer()` first; then reads each block file via `readBlock()` and assembles `data_out` (trims to `meta.size`).
- `deleteFile(path)`: `freeBlocks(meta.blocks)`, remove index entry, clear buffer if target path, `saveIndex()`.

Block helpers:
- `allocateBlocks(n)`: first-fit scan of `block_bitmap_` (0..MAX_BLOCKS-1), collects free indices; if `n` found, marks them true and returns vector; else returns empty. Complexity: O(MAX_BLOCKS) worst-case.
- `freeBlocks(block_ids)`: flip bitmap entries false (does not remove block files from disk).
- `freeBlockCount()`: count free bits.
- `writeBlock(block_id, data, len)`: write `/data/blocks/<block_id>` file (overwrite).
- `readBlock(block_id, buf, buf_size)`: read block file into buffer.

Utilities:
- `parentPath(path)` / `baseName(path)`: path parsing helpers.

**Coordinator client & server**

StorageClient (`src/coordinator.h` + `src/storage_client.cpp`):
- `StorageClient(host, port, secret)`: ctor.
- `connect()/disconnect()/isConnected()`: manage TCP socket.
- `sendAll()/recvAll()`: robust IO.
- `computeHMAC(data,len,out)`: HMAC-SHA256 using `secret_`.
- `sendFrame(type,payload)`: build magic|type|len|payload, compute tag over (type||len||payload), send frame.
- `recvFrame(frame)`: read frame, verify magic and HMAC, populate `MessageFrame`.
- RPC wrappers returning `AckResult`:
  - `write(path,data,owner,perms)`, `read(path,data_out)`, `remove(path)`, `list(path, entries_out)`, `mkdir(path, owner)`, `stat(path, stat_out)` — they pack payloads, call `sendFrame`/`recvFrame`, and populate `AckResult`.

Coordinator (`src/coordinator.cpp`):
- `Coordinator::Coordinator(...)`: ctor builds `StorageClient` instances and `AuthManager`.
- `run()`: connects to both storage nodes, listens on port 8080, accepts clients, and spawns a thread per client calling `handleClient()`.
- `handleClient(client_fd)`: text protocol handler for clients; supports `LOGIN`, `LOGOUT`, `WRITE`, `READ`, `DELETE`, `LIST`, `MKDIR`, `STAT`. Key points:
  - `WRITE`: parses byte count and bytes, permission check via `ensurePerm` (which calls `storage_a_.stat()`), `acquireWriteLock(path)`, forwards to `storage_a_.write()` and `storage_b_.write()` sequentially, `releaseWriteLock(path)`, returns OK only if both succeed.
  - `READ/LIST/STAT/MKDIR`: routed to `storage_a_` (reads may return from a single replica).
  - `DELETE`: lock, forward remove to both nodes, release.
- Locking:
  - `acquireWriteLock(path)`: per-path `WriteLock` map; waits on `wl->mtx` until available; if locked longer than `LOCK_TIMEOUT_SECONDS`, forcibly releases and logs WARN.
  - `releaseWriteLock(path)`: clears lock and notifies waiters.

**Storage node** — `src/storage_node.cpp`
- `computeHMAC(secret, data,len,out)` and `verifyHMAC(secret, signable_data, signable_len, received_hmac)`: HMAC helpers.
- `sendAck(fd, secret, type, payload)`: build framed ACK and HMAC and send.
- `permString(perms)`, `formatIso8601(t)`, `peerIpString(fd)`: formatting helpers.
- `handleConnection(client_fd, FileSystem& fs, secret)`: read framed request, verify magic and HMAC, unpack fields, call `fs` methods (`writeFile`, `readFile`, `deleteFile`, `listDirectory`, `createDirectory`, `getStat`), prepare `out_payload` or error, and `sendAck(...)` back. On invalid HMAC it logs and replies `MSG_ACK_ERR`.
- `main(argc,argv)`: parse `--port`/`--data`, read `DOCUVAULT_SECRET`, instantiate `FileSystem`, listen and spawn `handleConnection` per TCP connection.

**Tests / Test client** — `tests/test_client_final.cpp`
- `Connection` class: socket helper.
- Text protocol helpers: `sendLine`, `recvLine`, `sendRawBytes`, `recvBytes`.
- Test helpers: `doLogin`, `doWrite`, `doRead`, `doDelete`, `doStat`, `doMkdir`.
- Binary test helpers: send forged frame (invalid HMAC) and assert storage replies `ACK_ERR`.
- Test cases: cluster startup, routing, write/read/delete replication, HMAC rejection, write lock, deadlock timeout.

---

File created: [DOCS/API_SUMMARY.md](DOCS/API_SUMMARY.md)

Would you like me to (pick one):
- add this file to the repo's README with a link, or
- insert short clarifying comments into `src/fs.cpp` pointing out the buffer/index/block nuances?