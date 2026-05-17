#include "fs.h"
#include "protocol.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <openssl/hmac.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

// ===================================================================
// Storage Node — accepts binary-framed requests from the Coordinator,
// verifies HMAC authentication, executes file operations using your
// Checkpoint 1 FileSystem class, and sends ACK responses.
//
// This is a NEW entry point — it does NOT use the text-based command
// protocol from Checkpoint 1.  It reuses your FileSystem and block
// storage code, but wraps it in the binary message protocol defined
// in protocol.h.
// ===================================================================

// -------------------------------------------------------------------
// Low-level I/O helpers — do not modify
// -------------------------------------------------------------------

// sendAll(fd,buf,len): Send exactly `len` bytes from `buf` to `fd`.
// Returns true on success, false on error/EOF.
static bool sendAll(int fd, const void* buf, size_t len)
{
    const uint8_t* p = static_cast<const uint8_t*>(buf);
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, p + sent, len - sent, 0);
        if (n <= 0) return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

// recvAll(fd,buf,len): Receive exactly `len` bytes into `buf` from `fd`.
// Returns true on success, false on error/EOF.
static bool recvAll(int fd, void* buf, size_t len)
{
    uint8_t* p = static_cast<uint8_t*>(buf);
    size_t received = 0;
    while (received < len) {
        ssize_t n = recv(fd, p + received, len - received, 0);
        if (n <= 0) return false;
        received += static_cast<size_t>(n);
    }
    return true;
}

// ===================================================================
// HMAC VERIFICATION — implement this
// ===================================================================

// Compute HMAC-SHA256 over `data` (length `len`) using `secret`.
// Write the 32-byte result into `out`.
static void computeHMAC(const std::string& secret,
                        const uint8_t* data, size_t len,
                        uint8_t* out)
{
    unsigned int out_len = 0;
    unsigned char* r = ::HMAC(EVP_sha256(), secret.data(), static_cast<int>(secret.size()), 
                                data, len, out, &out_len);
    if (!r || out_len != HMAC_SIZE) {
        std::memset(out, 0, HMAC_SIZE);
    }
}

// Verify that the HMAC tag on a received frame is correct.
// Returns true if the tag matches.
// verifyHMAC(secret, signable_data, signable_len, received_hmac):
// Recomputes the HMAC for the provided signable bytes and returns
// true if it matches the received tag. Used to detect tampering or
// misconfiguration between Coordinator and Storage node.
static bool verifyHMAC(const std::string& secret,
                       const uint8_t* signable_data, size_t signable_len,
                       const uint8_t* received_hmac)
{
    uint8_t expected[HMAC_SIZE];
    computeHMAC(secret, signable_data, signable_len, expected);
    return std::memcmp(expected, received_hmac, HMAC_SIZE) == 0;
}

// ===================================================================
// FRAME SEND — implement this
// ===================================================================

// sendAck(fd,secret,type,payload): Build a framed response, sign it,
// and send it to `fd`. Returns true on success.
static bool sendAck(int fd, const std::string& secret,
                    MessageType type,
                    const std::vector<uint8_t>& payload)
{
    const uint32_t magic_n = htonl(PROTO_MAGIC);
    const uint8_t  type_b = static_cast<uint8_t>(type);
    const uint32_t len_n  = htonl(static_cast<uint32_t>(payload.size()));

    std::vector<uint8_t> signable;
    signable.reserve(1 + 4 + payload.size());
    signable.push_back(type_b);
    const uint8_t* len_bytes = reinterpret_cast<const uint8_t*>(&len_n);
    signable.insert(signable.end(), len_bytes, len_bytes + 4);
    signable.insert(signable.end(), payload.begin(), payload.end());

    uint8_t tag[HMAC_SIZE];
    computeHMAC(secret, signable.data(), signable.size(), tag);

    if (!sendAll(fd, &magic_n, sizeof(magic_n))) return false;
    if (!sendAll(fd, &type_b, sizeof(type_b))) return false;
    if (!sendAll(fd, &len_n, sizeof(len_n))) return false;
    if (!payload.empty() && !sendAll(fd, payload.data(), payload.size())) return false;
    if (!sendAll(fd, tag, sizeof(tag))) return false;
    return true;
}

// permString(perms): Render Unix-style permission bits as an rwx string.
static std::string permString(uint16_t perms)
{
    auto render = [](int field) {
        std::string s;
        s += (field & 4) ? 'r' : '-';
        s += (field & 2) ? 'w' : '-';
        s += (field & 1) ? 'x' : '-';
        return s;
    };

    int owner = (perms >> 6) & 0b111;
    int group = (perms >> 3) & 0b111;
    int other = perms & 0b111;
    return render(owner) + render(group) + render(other);
}

// formatIso8601(t): Format `t` as an ISO-8601 UTC timestamp string.
static std::string formatIso8601(std::time_t t)
{
    std::tm tm{};
#if defined(_WIN32)
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif

    char buf[32];
    if (std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm) == 0) {
        return "1970-01-01T00:00:00";
    }
    return std::string(buf);
}

// peerIpString(fd): Return the peer IP address of socket `fd` as string.
static std::string peerIpString(int fd)
{
    sockaddr_storage addr{};
    socklen_t len = sizeof(addr);
    if (::getpeername(fd, reinterpret_cast<sockaddr*>(&addr), &len) != 0) {
        return "unknown";
    }

    char ipbuf[INET6_ADDRSTRLEN] = {};
    if (addr.ss_family == AF_INET) {
        auto* a = reinterpret_cast<sockaddr_in*>(&addr);
        if (!::inet_ntop(AF_INET, &a->sin_addr, ipbuf, sizeof(ipbuf))) return "unknown";
        return std::string(ipbuf);
    }
    if (addr.ss_family == AF_INET6) {
        auto* a = reinterpret_cast<sockaddr_in6*>(&addr);
        if (!::inet_ntop(AF_INET6, &a->sin6_addr, ipbuf, sizeof(ipbuf))) return "unknown";
        return std::string(ipbuf);
    }
    return "unknown";
}

// ===================================================================
// CONNECTION HANDLER — implement this
// ===================================================================

// handleConnection(client_fd, fs, secret): Receives binary frames from
// the Coordinator, verifies the HMAC signature, dispatches filesystem
// operations on `fs`, and sends a signed ACK/ERR response for each
// processed message.
static void handleConnection(int client_fd,
                             FileSystem& fs,
                             const std::string& secret)
{
    const std::string peer_ip = peerIpString(client_fd);

    while (true) {
        uint32_t magic_n = 0;
        uint8_t type_b = 0;
        uint32_t len_n = 0;

        if (!recvAll(client_fd, &magic_n, sizeof(magic_n))) break;
        if (!recvAll(client_fd, &type_b, sizeof(type_b))) break;
        if (!recvAll(client_fd, &len_n, sizeof(len_n))) break;

        const uint32_t magic_h = ntohl(magic_n);
        const uint32_t payload_len = ntohl(len_n);

        std::vector<uint8_t> payload(payload_len);
        if (payload_len > 0) {
            if (!recvAll(client_fd, payload.data(), payload.size())) break;
        }

        uint8_t received_tag[HMAC_SIZE];
        if (!recvAll(client_fd, received_tag, sizeof(received_tag))) break;

        std::vector<uint8_t> signable;
        signable.reserve(1 + 4 + payload.size());
        signable.push_back(type_b);
        const uint8_t* len_bytes = reinterpret_cast<const uint8_t*>(&len_n);
        signable.insert(signable.end(), len_bytes, len_bytes + 4);
        signable.insert(signable.end(), payload.begin(), payload.end());

        if (magic_h != PROTO_MAGIC ||
            !verifyHMAC(secret, signable.data(), signable.size(), received_tag))
        {
            std::cerr << "WARN: rejected unauthenticated message from "
                      << peer_ip << std::endl;
            const std::string msg = "ERR_UNAUTHORIZED Invalid HMAC";
            sendAck(client_fd, secret, MSG_ACK_ERR,
                    std::vector<uint8_t>(msg.begin(), msg.end()));
            continue;
        }

        const MessageType msg_type = static_cast<MessageType>(type_b);
        std::vector<uint8_t> out_payload;
        MessageType out_type = MSG_ACK_OK;

        auto ackErr = [&](const std::string& err) {
            out_type = MSG_ACK_ERR;
            out_payload.assign(err.begin(), err.end());
        };

        if (msg_type == MSG_FORWARD_WRITE) {
            std::vector<std::string> fields;
            size_t data_offset = 0;
            if (!unpackFields(payload, 3, fields, data_offset)) {
                ackErr("ERR_BAD_REQUEST Invalid WRITE payload");
            } else {
                const std::string& path = fields[0];
                const std::string& owner = fields[1];
                (void)fields[2]; // perms string (not used by checkpoint FS)
                const std::string data(reinterpret_cast<const char*>(payload.data() + data_offset),
                                       payload.size() - data_offset);
                if (!fs.writeFile(path, data, owner)) {
                    ackErr("ERR_STORAGE_FAILURE Write failed");
                }
            }
        } else if (msg_type == MSG_FORWARD_READ) {
            std::vector<std::string> fields;
            size_t off = 0;
            if (!unpackFields(payload, 1, fields, off)) {
                ackErr("ERR_BAD_REQUEST Invalid READ payload");
            } else {
                std::string data;
                if (!fs.readFile(fields[0], data)) {
                    ackErr("ERR_NOT_FOUND Path not found");
                } else {
                    out_payload.assign(data.begin(), data.end());
                }
            }
        } else if (msg_type == MSG_FORWARD_DELETE) {
            std::vector<std::string> fields;
            size_t off = 0;
            if (!unpackFields(payload, 1, fields, off)) {
                ackErr("ERR_BAD_REQUEST Invalid DELETE payload");
            } else {
                if (!fs.deleteFile(fields[0])) {
                    ackErr("ERR_NOT_FOUND Path not found");
                }
            }
        } else if (msg_type == MSG_FORWARD_LIST) {
            std::vector<std::string> fields;
            size_t off = 0;
            if (!unpackFields(payload, 1, fields, off)) {
                ackErr("ERR_BAD_REQUEST Invalid LIST payload");
            } else {
                try {
                    auto entries = fs.listDirectory(fields[0]);
                    for (const auto& e : entries) {
                        const std::string type = e.is_dir ? "DIR" : "FILE";
                        const std::string line =
                            e.name + " " + type + " " +
                            std::to_string(e.size) + " " +
                            permString(e.perms);
                        out_payload.insert(out_payload.end(), line.begin(), line.end());
                        out_payload.push_back('\0');
                    }
                } catch (...) {
                    ackErr("ERR_NOT_FOUND Path not found");
                }
            }
        } else if (msg_type == MSG_FORWARD_MKDIR) {
            std::vector<std::string> fields;
            size_t off = 0;
            if (!unpackFields(payload, 2, fields, off)) {
                ackErr("ERR_BAD_REQUEST Invalid MKDIR payload");
            } else {
                const std::string& path = fields[0];
                const std::string& owner = fields[1];
                if (!fs.createDirectory(path, owner)) {
                    ackErr("ERR_BAD_REQUEST Cannot create directory");
                }
            }
        } else if (msg_type == MSG_FORWARD_STAT) {
            std::vector<std::string> fields;
            size_t off = 0;
            if (!unpackFields(payload, 1, fields, off)) {
                ackErr("ERR_BAD_REQUEST Invalid STAT payload");
            } else {
                try {
                    FileMetadata meta = fs.getStat(fields[0]);
                    const std::string perm = permString(meta.perms);
                    const std::string created = formatIso8601(meta.created);
                    const std::string modified = formatIso8601(meta.modified);
                    const std::string line =
                        "OK " + meta.name + " " + meta.owner + " " +
                        std::to_string(meta.size) + " " + perm + " " +
                        created + " " + modified;
                    out_payload.assign(line.begin(), line.end());
                } catch (...) {
                    ackErr("ERR_NOT_FOUND Path not found");
                }
            }
        } else {
            ackErr("ERR_BAD_REQUEST Unknown message type");
        }

        if (!sendAck(client_fd, secret, out_type, out_payload)) break;
    }

    close(client_fd);
}

// ===================================================================
// MAIN — do not modify
// ===================================================================

int main(int argc, char* argv[])
{
    int port = 9001;
    std::string data_dir = "/data/store";

    // Parse optional port override.
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--port" && i + 1 < argc) {
            port = std::atoi(argv[++i]);
        } else if (arg == "--data" && i + 1 < argc) {
            data_dir = argv[++i];
        }
    }

    // Read the shared secret from the environment.
    const char* env_secret = std::getenv("DOCUVAULT_SECRET");
    if (!env_secret || std::strlen(env_secret) == 0) {
        std::cerr << "ERROR: DOCUVAULT_SECRET environment variable not set"
                  << std::endl;
        return 1;
    }
    std::string secret = env_secret;

    // Initialize the file system (reuses your Checkpoint 1 code).
    FileSystem fs(data_dir);

    std::cout << "Storage node starting on port " << port << std::endl;

    // Create listening socket.
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        std::cerr << "ERROR: socket() failed: " << strerror(errno) << std::endl;
        return 1;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(static_cast<uint16_t>(port));

    if (bind(server_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::cerr << "ERROR: bind() failed: " << strerror(errno) << std::endl;
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 10) < 0) {
        std::cerr << "ERROR: listen() failed: " << strerror(errno) << std::endl;
        close(server_fd);
        return 1;
    }

    std::cout << "Storage node listening on port " << port << std::endl;

    // Accept loop — one thread per connection.
    while (true) {
        sockaddr_in client_addr{};
        socklen_t   client_len = sizeof(client_addr);
        int client_fd = accept(server_fd,
                               reinterpret_cast<sockaddr*>(&client_addr),
                               &client_len);
        if (client_fd < 0) {
            std::cerr << "WARN: accept() failed: " << strerror(errno)
                      << std::endl;
            continue;
        }
        std::thread(handleConnection, client_fd,
                    std::ref(fs), std::cref(secret)).detach();
    }

    close(server_fd);
    return 0;
}
