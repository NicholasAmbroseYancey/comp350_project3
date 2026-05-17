#ifndef DOCUVAULT_COORDINATOR_H
#define DOCUVAULT_COORDINATOR_H

#include "auth.h"
#include "protocol.h"

#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

// ---------------------------------------------------------------------------
// AckResult — returned by every StorageClient RPC method
// ---------------------------------------------------------------------------

struct AckResult {
    bool        success = false;
    std::string error_msg;          // populated on failure
    std::string data;               // populated by read() and stat()
    std::vector<std::string> entries;  // populated by list()
};

// ---------------------------------------------------------------------------
// StorageClient — RPC abstraction for Coordinator → Storage communication
//
// Each instance wraps a persistent TCP connection to one Storage node.
// Methods handle binary framing, HMAC signing, sending, receiving, and
// response parsing internally.  From the Coordinator's perspective,
// calling storage.write(...) looks like a regular function call.
//
// Students implement every method in storage_client.cpp.
// ---------------------------------------------------------------------------

class StorageClient {
public:
    // Construct with connection parameters and the shared secret.
    StorageClient(const std::string& host, int port,
                  const std::string& secret);
    ~StorageClient();

    // Disable copying — each client owns a socket.
    StorageClient(const StorageClient&)            = delete;
    StorageClient& operator=(const StorageClient&) = delete;

    // Establish the TCP connection to the storage node.
    // Returns true on success.  May be called again after disconnect().
    bool connect();

    // Close the connection.
    void disconnect();

    // True if the socket is currently open.
    bool isConnected() const;

    // ---- RPC methods ----

    AckResult write(const std::string& path,
                    const std::string& data,
                    const std::string& owner,
                    uint16_t perms);

    AckResult read(const std::string& path,
                   std::string& data_out);

    AckResult remove(const std::string& path);

    AckResult list(const std::string& path,
                   std::vector<std::string>& entries_out);

    AckResult mkdir(const std::string& path,
                    const std::string& owner);

    AckResult stat(const std::string& path,
                   std::string& stat_out);

private:
    // Build a MessageFrame with the given type and payload, compute
    // the HMAC tag, and send the entire frame over the socket.
    // Returns true on success.
    bool sendFrame(MessageType type,
                   const std::vector<uint8_t>& payload);

    // Read a complete MessageFrame from the socket and verify its
    // HMAC tag.  Returns true if a valid frame was received.
    bool recvFrame(MessageFrame& frame);

    // Compute HMAC-SHA256 over `data` (length `len`) using secret_
    // and write the 32-byte tag into `out`.
    void computeHMAC(const uint8_t* data, size_t len,
                     uint8_t* out) const;

    // Low-level: send exactly `len` bytes.
    bool sendAll(const void* buf, size_t len);

    // Low-level: receive exactly `len` bytes.
    bool recvAll(void* buf, size_t len);

    std::string host_;
    int         port_;
    std::string secret_;
    int         fd_ = -1;
    std::mutex  io_mutex_;   // serializes send/recv on this connection
};

// ---------------------------------------------------------------------------
// WriteLock — per-file write lock with timeout-based deadlock recovery
// ---------------------------------------------------------------------------

struct WriteLock {
    std::mutex              mtx;
    std::condition_variable cv;
    bool                    locked = false;
    std::chrono::steady_clock::time_point acquired_at;
};

// ---------------------------------------------------------------------------
// Coordinator — routes client requests to a pair of Storage nodes
//
// Students implement the handler methods and lock management in
// coordinator.cpp.  The main() function and accept loop are provided
// as a scaffold.
// ---------------------------------------------------------------------------

class Coordinator {
public:
    Coordinator(int port,
                const std::string& secret,
                const std::string& storage_a_host, int storage_a_port,
                const std::string& storage_b_host, int storage_b_port,
                const std::string& user_file,
                int lock_timeout_seconds);

    // Start listening and enter the accept loop (blocks forever).
    void run();

private:
    // Per-client handler (runs in its own thread).
    void handleClient(int client_fd);

    // ---- Write lock management ----

    // Acquire the write lock for `path`.  Blocks until the lock is
    // available or the timeout expires.
    // Returns true if the lock was acquired, false on timeout
    // (in which case the WARN log line must be emitted and the
    // stale lock forcibly released).
    bool acquireWriteLock(const std::string& path);

    // Release the write lock for `path`.
    void releaseWriteLock(const std::string& path);

    // ---- I/O helpers (same as Checkpoint 1) ----

    static std::string readLine(int fd);
    static void        sendResponse(int fd, const std::string& msg);
    static std::string readBytes(int fd, size_t n);
    static void        sendRaw(int fd, const char* data, size_t len);
    static std::vector<std::string> tokenize(const std::string& line);

    // ---- Member data ----

    int            port_;
    std::string    secret_;
    AuthManager    auth_;
    int            lock_timeout_s_;

    StorageClient  storage_a_;
    StorageClient  storage_b_;

    // Guards the write_locks_ map itself (not individual locks).
    std::mutex     locks_map_mutex_;
    std::unordered_map<std::string, std::shared_ptr<WriteLock>> write_locks_;
};

#endif // DOCUVAULT_COORDINATOR_H
