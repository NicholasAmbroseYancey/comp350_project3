#include "coordinator.h"

/*
 * coordinator.cpp
 *
 * Coordinator is the brain of the cluster, managing replication and
 * concurrency. Key behaviors implemented here:
 *  - Coordinator(...): Constructor sets up storage connection params,
 *      shared secret, auth file, and lock timeout.
 *  - run(): Initializes connections to both storage nodes and enters
 *      the main accept loop; spawns a thread per client connection.
 *  - handleClient(fd): Main request dispatcher for a client session.
 *      Manages LOGIN/LOGOUT state and routes commands (WRITE, READ,
 *      DELETE, LIST, MKDIR, STAT) to storage nodes.
 *  - acquireWriteLock(path): Implements per-file write locking with
 *      timeout-based deadlock recovery (forced release on stale locks).
 *  - releaseWriteLock(path): Releases a per-file lock and notifies
 *      waiters.
 *  - readLine / readBytes / sendResponse / sendRaw / tokenize:
 *      I/O helpers for simple line and raw byte communication.
 *
 * The file contains the accept loop and helper scaffolding used by the
 * Coordinator class implemented in coordinator.h.
 */

#include <arpa/inet.h>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string_view>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

// ===================================================================
// I/O HELPERS — reused from Checkpoint 1, do not modify
// ===================================================================

// readLine(fd): Read a newline-terminated line from `fd` and return it
// without the trailing newline. Returns empty string on EOF/error.
std::string Coordinator::readLine(int fd)
{
    std::string line;
    char c;
    while (true) {
        ssize_t n = recv(fd, &c, 1, 0);
        if (n <= 0) return "";
        if (c == '\n') return line;
        line += c;
    }
}

// sendResponse(fd,msg): Send a textual response terminated by newline
// to the client file descriptor.
void Coordinator::sendResponse(int fd, const std::string& msg)
{
    std::string full = msg + "\n";
    sendRaw(fd, full.c_str(), full.size());
}

// readBytes(fd,n): Read exactly `n` bytes from `fd` or return fewer on
// EOF; used to receive raw payloads from clients.
std::string Coordinator::readBytes(int fd, size_t n)
{
    std::string buf(n, '\0');
    size_t received = 0;
    while (received < n) {
        ssize_t r = recv(fd, &buf[received], n - received, 0);
        if (r <= 0) { buf.resize(received); return buf; }
        received += static_cast<size_t>(r);
    }
    return buf;
}

// sendRaw(fd,data,len): Ensure all `len` bytes are written to `fd`.
void Coordinator::sendRaw(int fd, const char* data, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, data + sent, len - sent, 0);
        if (n <= 0) return;
        sent += static_cast<size_t>(n);
    }
}

// tokenize(line): Split a whitespace-separated command line into tokens.
std::vector<std::string> Coordinator::tokenize(const std::string& line)
{
    std::vector<std::string> tokens;
    std::istringstream stream(line);
    std::string token;
    while (stream >> token) tokens.push_back(token);
    return tokens;
}

// ===================================================================
// CONSTRUCTOR
// ===================================================================

// Coordinator(...): Initialize coordinator settings, storage clients,
// and authentication manager.
Coordinator::Coordinator(int port,
                                                 const std::string& secret,
                                                 const std::string& sa_host, int sa_port,
                                                 const std::string& sb_host, int sb_port,
                                                 const std::string& user_file,
                                                 int lock_timeout_seconds)
        : port_(port),
            secret_(secret),
            auth_(user_file),
            lock_timeout_s_(lock_timeout_seconds),
            storage_a_(sa_host, sa_port, secret),
            storage_b_(sb_host, sb_port, secret)
{
}

// ===================================================================
// RUN — accept loop, do not modify
// ===================================================================

// run(): The main execution loop that initializes connections to both
// storage nodes and starts the TCP server to accept client requests.
// Spawns a detached thread per client connection.
void Coordinator::run()
{
    // Connect to both storage nodes.
    if (!storage_a_.connect()) {
        std::cerr << "ERROR: cannot connect to storage-a" << std::endl;
        return;
    }
    if (!storage_b_.connect()) {
        std::cerr << "ERROR: cannot connect to storage-b" << std::endl;
        return;
    }

    std::cout << "Coordinator connected to both storage nodes" << std::endl;

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        std::cerr << "ERROR: socket() failed: " << strerror(errno) << std::endl;
        return;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(static_cast<uint16_t>(port_));

    if (bind(server_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::cerr << "ERROR: bind() failed: " << strerror(errno) << std::endl;
        close(server_fd);
        return;
    }

    if (listen(server_fd, 10) < 0) {
        std::cerr << "ERROR: listen() failed: " << strerror(errno) << std::endl;
        close(server_fd);
        return;
    }

    std::cout << "Coordinator listening on port " << port_ << std::endl;

    while (true) {
        sockaddr_in client_addr{};
        socklen_t   client_len = sizeof(client_addr);
        int client_fd = accept(server_fd,
                               reinterpret_cast<sockaddr*>(&client_addr),
                               &client_len);
        if (client_fd < 0) {
            std::cerr << "WARN: accept() failed: " << strerror(errno) << std::endl;
            continue;
        }
        std::thread(&Coordinator::handleClient, this, client_fd).detach();
    }

    close(server_fd);
}

// ===================================================================
// CLIENT HANDLER — dispatcher scaffold, implement the handlers
// ===================================================================

// handleClient(client_fd): Manages the lifecycle of a single user
// session: reads commands, checks authentication, acquires locks when
// needed, and coordinates storage node RPCs to satisfy client requests.
void Coordinator::handleClient(int client_fd)
{
    struct Session {
        bool authenticated = false;
        std::string username;
    };

    auto parseOtherPermBits = [](std::string_view perm9) -> int {
        // perm9 like "rwx------" (9 chars). Return other 3-bit field (0..7).
        if (perm9.size() < 9) return 0;
        int bits = 0;
        if (perm9[6] == 'r') bits |= 4;
        if (perm9[7] == 'w') bits |= 2;
        if (perm9[8] == 'x') bits |= 1;
        return bits;
    };

    auto ensurePerm = [&](const std::string& path, const std::string& username, int neededBits) -> bool {
        std::string stat_line;
        AckResult st = storage_a_.stat(path, stat_line);
        if (!st.success) return true; // storage will return the real error later

        auto toks = tokenize(stat_line);
        if (toks.size() < 7 || toks[0] != "OK") return true;
        const std::string& owner = toks[2];
        const std::string& perm9 = toks[4];
        if (owner == username) return true;
        return (parseOtherPermBits(perm9) & neededBits) == neededBits;
    };

    Session session;

    while (true) {
        std::string line = readLine(client_fd);
        if (line.empty()) break;

        std::vector<std::string> tokens = tokenize(line);
        if (tokens.empty()) continue;

        const std::string& cmd = tokens[0];
        std::vector<std::string> args(tokens.begin() + 1, tokens.end());

        if (!session.authenticated && cmd != "LOGIN") {
            sendResponse(client_fd, "ERR_UNAUTHORIZED Not logged in");
            continue;
        }

        if (cmd == "LOGIN") {
            if (args.size() != 2) {
                sendResponse(client_fd, "ERR_BAD_REQUEST Invalid LOGIN syntax");
                continue;
            }
            if (auth_.authenticate(args[0], args[1])) {
                session.authenticated = true;
                session.username = args[0];
                sendResponse(client_fd, "OK Logged in");
            } else {
                sendResponse(client_fd, "ERR_UNAUTHORIZED Invalid credentials");
            }
            continue;
        }

        if (cmd == "LOGOUT") {
            session.authenticated = false;
            session.username.clear();
            sendResponse(client_fd, "OK Logged out");
            continue;
        }

        if (cmd == "WRITE") {
            if (args.size() != 2) {
                sendResponse(client_fd, "ERR_BAD_REQUEST Invalid WRITE syntax");
                continue;
            }

            const std::string& path = args[0];
            long long bc_ll = -1;
            try {
                size_t idx = 0;
                bc_ll = std::stoll(args[1], &idx);
                if (idx != args[1].size()) {
                    sendResponse(client_fd, "ERR_BAD_REQUEST Invalid byte count");
                    continue;
                }
            } catch (...) {
                sendResponse(client_fd, "ERR_BAD_REQUEST Invalid byte count");
                continue;
            }
            if (bc_ll < 0) {
                sendResponse(client_fd, "ERR_BAD_REQUEST Invalid byte count");
                continue;
            }

            const size_t byte_count = static_cast<size_t>(bc_ll);
            std::string data = readBytes(client_fd, byte_count);
            if (data.size() != byte_count) {
                sendResponse(client_fd, "ERR_BAD_REQUEST Client disconnected mid-transfer");
                continue;
            }

            if (!ensurePerm(path, session.username, 2 /* write */)) {
                sendResponse(client_fd, "ERR_UNAUTHORIZED Permission denied");
                continue;
            }

            acquireWriteLock(path);
            AckResult a = storage_a_.write(path, data, session.username, 0600);
            AckResult b = storage_b_.write(path, data, session.username, 0600);
            releaseWriteLock(path);

            if (!a.success || !b.success) {
                sendResponse(client_fd, "ERR_STORAGE_FAILURE Storage failure");
            } else {
                sendResponse(client_fd, "OK Written");
            }
            continue;
        }

        if (cmd == "READ") {
            if (args.size() != 1) {
                sendResponse(client_fd, "ERR_BAD_REQUEST Invalid READ syntax");
                continue;
            }

            const std::string& path = args[0];
            if (!ensurePerm(path, session.username, 4 /* read */)) {
                sendResponse(client_fd, "ERR_UNAUTHORIZED Permission denied");
                continue;
            }

            std::string data_out;
            AckResult r = storage_a_.read(path, data_out);
            if (!r.success) {
                sendResponse(client_fd, r.error_msg.empty() ? "ERR_NOT_FOUND Path not found" : r.error_msg);
                continue;
            }

            sendResponse(client_fd, "OK " + std::to_string(data_out.size()));
            if (!data_out.empty()) {
                sendRaw(client_fd, data_out.data(), data_out.size());
            }
            continue;
        }

        if (cmd == "DELETE") {
            if (args.size() != 1) {
                sendResponse(client_fd, "ERR_BAD_REQUEST Invalid DELETE syntax");
                continue;
            }

            const std::string& path = args[0];
            if (!ensurePerm(path, session.username, 2 /* write */)) {
                sendResponse(client_fd, "ERR_UNAUTHORIZED Permission denied");
                continue;
            }

            acquireWriteLock(path);
            AckResult a = storage_a_.remove(path);
            AckResult b = storage_b_.remove(path);
            releaseWriteLock(path);

            if (!a.success || !b.success) {
                sendResponse(client_fd, "ERR_STORAGE_FAILURE Storage failure");
            } else {
                sendResponse(client_fd, "OK Deleted");
            }
            continue;
        }

        if (cmd == "LIST") {
            if (args.size() != 1) {
                sendResponse(client_fd, "ERR_BAD_REQUEST Invalid LIST syntax");
                continue;
            }

            const std::string& path = args[0];
            if (!ensurePerm(path, session.username, 4 /* read */)) {
                sendResponse(client_fd, "ERR_UNAUTHORIZED Permission denied");
                continue;
            }

            std::vector<std::string> entries;
            AckResult r = storage_a_.list(path, entries);
            if (!r.success) {
                sendResponse(client_fd, r.error_msg.empty() ? "ERR_NOT_FOUND Path not found" : r.error_msg);
                continue;
            }

            sendResponse(client_fd, "OK " + std::to_string(entries.size()));
            for (const auto& e : entries) {
                sendResponse(client_fd, e);
            }
            continue;
        }

        if (cmd == "MKDIR") {
            if (args.size() != 1) {
                sendResponse(client_fd, "ERR_BAD_REQUEST Invalid MKDIR syntax");
                continue;
            }

            // Replicate directory creation so subsequent replicated WRITEs
            // to nested paths succeed on both storage nodes.
            AckResult a = storage_a_.mkdir(args[0], session.username);
            AckResult b = storage_b_.mkdir(args[0], session.username);
            if (!a.success || !b.success) {
                sendResponse(client_fd, "ERR_STORAGE_FAILURE Storage failure");
            } else {
                sendResponse(client_fd, "OK Directory created");
            }
            continue;
        }

        if (cmd == "STAT") {
            if (args.size() != 1) {
                sendResponse(client_fd, "ERR_BAD_REQUEST Invalid STAT syntax");
                continue;
            }

            std::string stat_out;
            AckResult r = storage_a_.stat(args[0], stat_out);
            if (!r.success) {
                sendResponse(client_fd, r.error_msg.empty() ? "ERR_NOT_FOUND Path not found" : r.error_msg);
            } else {
                sendResponse(client_fd, stat_out);
            }
            continue;
        }

        sendResponse(client_fd, "ERR_BAD_REQUEST Unknown command");
    }

    close(client_fd);
}

// ===================================================================
// WRITE LOCK MANAGEMENT — implement both methods
// ===================================================================

// acquireWriteLock(path): Uses a per-path condition variable and a
// timeout-based lease (lock_timeout_s_) to ensure only one thread may
// write a specific file at a time. If the lock appears stale, it is
// forcibly released after the configured timeout.
bool Coordinator::acquireWriteLock(const std::string& path)
{
    std::shared_ptr<WriteLock> wl;
    {
        std::lock_guard<std::mutex> map_lock(locks_map_mutex_);
        auto it = write_locks_.find(path);
        if (it == write_locks_.end()) {
            wl = std::make_shared<WriteLock>();
            write_locks_[path] = wl;
        } else {
            wl = it->second;
        }
    }

    std::unique_lock<std::mutex> lock(wl->mtx);
    const auto timeout = std::chrono::seconds(lock_timeout_s_);

    while (wl->locked) {
        auto now = std::chrono::steady_clock::now();
        auto waited = wl->cv.wait_for(lock, timeout);
        (void)waited;
        now = std::chrono::steady_clock::now();

        if (wl->locked && (now - wl->acquired_at) >= timeout) {
            wl->locked = false;
            std::cerr << "WARN: forced lock release on " << path
                      << " after timeout" << std::endl;
            wl->cv.notify_all();
            break;
        }
    }

    wl->locked = true;
    wl->acquired_at = std::chrono::steady_clock::now();
    return true;
}

// releaseWriteLock(path): Clears the lock flag for `path` and notifies
// any waiting threads that the resource is available.
void Coordinator::releaseWriteLock(const std::string& path)
{
    std::shared_ptr<WriteLock> wl;
    {
        std::lock_guard<std::mutex> map_lock(locks_map_mutex_);
        auto it = write_locks_.find(path);
        if (it == write_locks_.end()) return;
        wl = it->second;
    }

    {
        std::lock_guard<std::mutex> lock(wl->mtx);
        wl->locked = false;
    }
    wl->cv.notify_all();
}

// ===================================================================
// MAIN — reads configuration from environment variables
// ===================================================================

int main()
{
    // Read configuration from environment variables.
    // docker-compose.yml sets all of these.
    int port = 8080;

    const char* env_secret  = std::getenv("DOCUVAULT_SECRET");
    const char* env_timeout = std::getenv("LOCK_TIMEOUT_SECONDS");
    const char* env_sa_host = std::getenv("STORAGE_A_HOST");
    const char* env_sa_port = std::getenv("STORAGE_A_PORT");
    const char* env_sb_host = std::getenv("STORAGE_B_HOST");
    const char* env_sb_port = std::getenv("STORAGE_B_PORT");
    const char* env_users   = std::getenv("USERS_FILE");

    std::string secret       = env_secret  ? env_secret  : "default_secret";
    int         lock_timeout = env_timeout ? std::atoi(env_timeout) : 5;
    std::string sa_host      = env_sa_host ? env_sa_host : "storage-a";
    int         sa_port      = env_sa_port ? std::atoi(env_sa_port) : 9001;
    std::string sb_host      = env_sb_host ? env_sb_host : "storage-b";
    int         sb_port      = env_sb_port ? std::atoi(env_sb_port) : 9002;
    std::string user_file    = env_users   ? env_users   : "/data/users.txt";

    std::cout << "Coordinator starting..." << std::endl;
    std::cout << "  Storage A: " << sa_host << ":" << sa_port << std::endl;
    std::cout << "  Storage B: " << sb_host << ":" << sb_port << std::endl;
    std::cout << "  Lock timeout: " << lock_timeout << "s" << std::endl;

    Coordinator coord(port, secret,
                      sa_host, sa_port,
                      sb_host, sb_port,
                      user_file, lock_timeout);
    coord.run();

    return 0;
}

// main(): Read environment configuration, construct a Coordinator
// instance and start its main loop.
