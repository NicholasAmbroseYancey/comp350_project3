#include "coordinator.h"

/*
 * storage_client.cpp
 *
 * RPC abstraction used by the Coordinator to communicate with a Storage node.
 * Responsibilities:
 *  - connect()/disconnect(): resolve host and establish/close TCP connection.
 *  - sendAll()/recvAll(): low-level helpers to ensure exact-byte I/O.
 *  - computeHMAC(...): compute 32-byte HMAC-SHA256 using the shared secret.
 *  - sendFrame(type,payload): build the binary frame, sign it, and send.
 *  - recvFrame(frame): receive a frame, verify magic and HMAC, and parse.
 *  - write/read/remove/list/mkdir/stat: high-level RPC methods that make
 *      Coordinator code read like local function calls and translate
 *      responses/errors into AckResult or exceptions.
 */

#include <arpa/inet.h>
#include <chrono>
#include <cstring>
#include <iostream>
#include <netdb.h>
#include <openssl/hmac.h>
#include <sys/socket.h>
#include <unistd.h>

// ===================================================================
// Construction / Connection
// ===================================================================

// StorageClient(host,port,secret): Construct a client that can
// communicate with a storage node using the given shared secret.
StorageClient::StorageClient(const std::string& host, int port,
                             const std::string& secret)
    : host_(host), port_(port), secret_(secret)
{
}

// ~StorageClient(): Ensure the socket is closed on destruction.
StorageClient::~StorageClient()
{
    disconnect();
}

// connect(): Resolve the host and establish a TCP connection with a
// short timeout; returns true on success.
bool StorageClient::connect()
{
    disconnect();

    addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo* res = nullptr;
    const std::string port_str = std::to_string(port_);
    int rc = ::getaddrinfo(host_.c_str(), port_str.c_str(), &hints, &res);
    if (rc != 0 || !res) {
        std::cerr << "ERROR: getaddrinfo(" << host_ << "): "
                  << (rc != 0 ? gai_strerror(rc) : "no results")
                  << std::endl;
        return false;
    }

    int sock = -1;
    for (addrinfo* p = res; p; p = p->ai_next) {
        sock = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock < 0) continue;

        timeval tv{};
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        (void)::setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        (void)::setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        if (::connect(sock, p->ai_addr, p->ai_addrlen) == 0) {
            fd_ = sock;
            ::freeaddrinfo(res);
            return true;
        }

        ::close(sock);
        sock = -1;
    }

    ::freeaddrinfo(res);
    return false;
}


// disconnect(): Close the underlying socket if connected.
void StorageClient::disconnect()
{
    if (fd_ >= 0) {
        close(fd_);
        fd_ = -1;
    }
}


// isConnected(): Return true if the TCP socket is currently open.
bool StorageClient::isConnected() const
{
    return fd_ >= 0;
}

// ===================================================================
// Low-level I/O
// ===================================================================

// sendAll(buf,len): Send all bytes from `buf` over the socket.
bool StorageClient::sendAll(const void* buf, size_t len)
{
    if (fd_ < 0) return false;
    const uint8_t* p = static_cast<const uint8_t*>(buf);
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = ::send(fd_, p + sent, len - sent, 0);
        if (n <= 0) return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

// recvAll(buf,len): Receive exactly `len` bytes into `buf`.
bool StorageClient::recvAll(void* buf, size_t len)
{
    if (fd_ < 0) return false;
    uint8_t* p = static_cast<uint8_t*>(buf);
    size_t received = 0;
    while (received < len) {
        ssize_t n = ::recv(fd_, p + received, len - received, 0);
        if (n <= 0) return false;
        received += static_cast<size_t>(n);
    }
    return true;
}

// ===================================================================
// HMAC computation
// ===================================================================

void StorageClient::computeHMAC(const uint8_t* data, size_t len,
                                uint8_t* out) const
{
    unsigned int out_len = 0;
    unsigned char* r = ::HMAC(EVP_sha256(),
                              secret_.data(),
                              static_cast<int>(secret_.size()),
                              data,
                              len,
                              out,
                              &out_len);
    if (!r || out_len != HMAC_SIZE) {
        std::memset(out, 0, HMAC_SIZE);
    }
}


// ===================================================================
// Frame send / receive
// ===================================================================

bool StorageClient::sendFrame(MessageType type, const std::vector<uint8_t>& payload) {
    // Guard concurrent I/O on the socket — serialize send/recv calls.
    std::lock_guard<std::mutex> lock(io_mutex_);

    // Ensure socket is connected. If not connected, try to establish one.
    // If `connect()` fails, abort the send.
    if (fd_ < 0 && !connect()) return false;
    if (fd_ < 0) return false;

    // Prepare header fields in network byte order:
    // - magic_n: protocol magic (4 bytes, network order)
    // - type_b: single-byte message type
    // - len_n: 4-byte payload length (network order)
    const uint32_t magic_n = htonl(PROTO_MAGIC);
    const uint8_t  type_b = static_cast<uint8_t>(type);
    const uint32_t len_n  = htonl(static_cast<uint32_t>(payload.size()));

    // Build the byte sequence that will be covered by the HMAC.
    // HMAC covers: [type (1)] [len (4)] [payload (len)].
    std::vector<uint8_t> signable;
    signable.reserve(1 + 4 + payload.size());
    signable.push_back(type_b);
    const uint8_t* len_bytes = reinterpret_cast<const uint8_t*>(&len_n);
    signable.insert(signable.end(), len_bytes, len_bytes + 4);
    signable.insert(signable.end(), payload.begin(), payload.end());

    // Compute HMAC-SHA256 over the signable bytes. The resulting tag
    // will be appended to the frame on the wire for integrity/authenticity.
    uint8_t tag[HMAC_SIZE];
    computeHMAC(signable.data(), signable.size(), tag);

    // Transmit frame in the wire format:
    // [magic (4)] [type (1)] [len (4)] [payload (len)] [hmac (32)]
    if (!sendAll(&magic_n, sizeof(magic_n))) return false;
    if (!sendAll(&type_b, sizeof(type_b))) return false;
    if (!sendAll(&len_n, sizeof(len_n))) return false;
    if (!payload.empty() && !sendAll(payload.data(), payload.size())) return false;
    if (!sendAll(tag, sizeof(tag))) return false;

    return true;
}

bool StorageClient::recvFrame(MessageFrame& frame)
{
    std::lock_guard<std::mutex> lock(io_mutex_);

    if (fd_ < 0) return false;

    uint32_t magic_n = 0;
    uint8_t  type_b = 0;
    uint32_t len_n = 0;

    if (!recvAll(&magic_n, sizeof(magic_n))) return false;
    if (!recvAll(&type_b, sizeof(type_b))) return false;
    if (!recvAll(&len_n, sizeof(len_n))) return false;

    const uint32_t magic_h = ntohl(magic_n);
    if (magic_h != PROTO_MAGIC) return false;

    const uint32_t payload_len = ntohl(len_n);
    std::vector<uint8_t> payload(payload_len);
    if (payload_len > 0) {
        if (!recvAll(payload.data(), payload.size())) return false;
    }

    uint8_t received_tag[HMAC_SIZE];
    if (!recvAll(received_tag, sizeof(received_tag))) return false;

    std::vector<uint8_t> signable;
    signable.reserve(1 + 4 + payload.size());
    signable.push_back(type_b);
    const uint8_t* len_bytes = reinterpret_cast<const uint8_t*>(&len_n);
    signable.insert(signable.end(), len_bytes, len_bytes + 4);
    signable.insert(signable.end(), payload.begin(), payload.end());

    uint8_t expected[HMAC_SIZE];
    computeHMAC(signable.data(), signable.size(), expected);
    if (std::memcmp(expected, received_tag, HMAC_SIZE) != 0) return false;

    frame.magic = magic_h;
    frame.msg_type = static_cast<MessageType>(type_b);
    frame.payload_len = payload_len;
    frame.payload = std::move(payload);
    std::memcpy(frame.hmac, received_tag, HMAC_SIZE);
    return true;
}


// ===================================================================
// RPC methods
// ===================================================================

AckResult StorageClient::write(const std::string& path,
                               const std::string& data,
                               const std::string& owner,
                               uint16_t perms)
{
    AckResult r;

    const std::vector<uint8_t> payload =
        packFields({path, owner, std::to_string(static_cast<unsigned int>(perms))},
                   data);

    if (!sendFrame(MSG_FORWARD_WRITE, payload)) {
        disconnect();
        r.success = false;
        r.error_msg = "ERR_STORAGE_FAILURE Failed to contact storage";
        return r;
    }

    MessageFrame frame;
    if (!recvFrame(frame)) {
        disconnect();
        r.success = false;
        r.error_msg = "ERR_STORAGE_FAILURE Invalid response from storage";
        return r;
    }

    if (frame.msg_type == MSG_ACK_OK) {
        r.success = true;
        return r;
    }

    r.success = false;
    r.error_msg.assign(frame.payload.begin(), frame.payload.end());
    if (r.error_msg.empty()) r.error_msg = "ERR_STORAGE_FAILURE Storage error";
    return r;
}


AckResult StorageClient::read(const std::string& path,
                              std::string& data_out)
{
    AckResult r;
    data_out.clear();

    const std::vector<uint8_t> payload = packFields({path});
    if (!sendFrame(MSG_FORWARD_READ, payload)) {
        disconnect();
        r.success = false;
        r.error_msg = "ERR_STORAGE_FAILURE Failed to contact storage";
        return r;
    }

    MessageFrame frame;
    if (!recvFrame(frame)) {
        disconnect();
        r.success = false;
        r.error_msg = "ERR_STORAGE_FAILURE Invalid response from storage";
        return r;
    }

    if (frame.msg_type != MSG_ACK_OK) {
        r.success = false;
        r.error_msg.assign(frame.payload.begin(), frame.payload.end());
        if (r.error_msg.empty()) r.error_msg = "ERR_STORAGE_FAILURE Storage error";
        return r;
    }

    data_out.assign(frame.payload.begin(), frame.payload.end());
    r.success = true;
    r.data = data_out;
    return r;
}


AckResult StorageClient::remove(const std::string& path)
{
    AckResult r;
    const std::vector<uint8_t> payload = packFields({path});
    if (!sendFrame(MSG_FORWARD_DELETE, payload)) {
        disconnect();
        r.success = false;
        r.error_msg = "ERR_STORAGE_FAILURE Failed to contact storage";
        return r;
    }
    MessageFrame frame;
    if (!recvFrame(frame)) {
        disconnect();
        r.success = false;
        r.error_msg = "ERR_STORAGE_FAILURE Invalid response from storage";
        return r;
    }
    if (frame.msg_type == MSG_ACK_OK) {
        r.success = true;
        return r;
    }
    r.success = false;
    r.error_msg.assign(frame.payload.begin(), frame.payload.end());
    if (r.error_msg.empty()) r.error_msg = "ERR_STORAGE_FAILURE Storage error";
    return r;
}


AckResult StorageClient::list(const std::string& path,
                              std::vector<std::string>& entries_out)
{
    AckResult r;
    entries_out.clear();

    const std::vector<uint8_t> payload = packFields({path});
    if (!sendFrame(MSG_FORWARD_LIST, payload)) {
        disconnect();
        r.success = false;
        r.error_msg = "ERR_STORAGE_FAILURE Failed to contact storage";
        return r;
    }

    MessageFrame frame;
    if (!recvFrame(frame)) {
        disconnect();
        r.success = false;
        r.error_msg = "ERR_STORAGE_FAILURE Invalid response from storage";
        return r;
    }

    if (frame.msg_type != MSG_ACK_OK) {
        r.success = false;
        r.error_msg.assign(frame.payload.begin(), frame.payload.end());
        if (r.error_msg.empty()) r.error_msg = "ERR_STORAGE_FAILURE Storage error";
        return r;
    }

    std::string joined(frame.payload.begin(), frame.payload.end());
    size_t pos = 0;
    while (pos < joined.size()) {
        size_t end = joined.find('\0', pos);
        if (end == std::string::npos) end = joined.size();
        if (end > pos) {
            entries_out.push_back(joined.substr(pos, end - pos));
        }
        pos = end + 1;
    }

    r.success = true;
    r.entries = entries_out;
    return r;
}


AckResult StorageClient::mkdir(const std::string& path,
                               const std::string& owner)
{
    AckResult r;
    const std::vector<uint8_t> payload = packFields({path, owner});
    if (!sendFrame(MSG_FORWARD_MKDIR, payload)) {
        disconnect();
        r.success = false;
        r.error_msg = "ERR_STORAGE_FAILURE Failed to contact storage";
        return r;
    }
    MessageFrame frame;
    if (!recvFrame(frame)) {
        disconnect();
        r.success = false;
        r.error_msg = "ERR_STORAGE_FAILURE Invalid response from storage";
        return r;
    }
    if (frame.msg_type == MSG_ACK_OK) {
        r.success = true;
        return r;
    }
    r.success = false;
    r.error_msg.assign(frame.payload.begin(), frame.payload.end());
    if (r.error_msg.empty()) r.error_msg = "ERR_STORAGE_FAILURE Storage error";
    return r;
}


AckResult StorageClient::stat(const std::string& path,
                              std::string& stat_out)
{
    AckResult r;
    stat_out.clear();

    const std::vector<uint8_t> payload = packFields({path});
    if (!sendFrame(MSG_FORWARD_STAT, payload)) {
        disconnect();
        r.success = false;
        r.error_msg = "ERR_STORAGE_FAILURE Failed to contact storage";
        return r;
    }

    MessageFrame frame;
    if (!recvFrame(frame)) {
        disconnect();
        r.success = false;
        r.error_msg = "ERR_STORAGE_FAILURE Invalid response from storage";
        return r;
    }

    if (frame.msg_type != MSG_ACK_OK) {
        r.success = false;
        r.error_msg.assign(frame.payload.begin(), frame.payload.end());
        if (r.error_msg.empty()) r.error_msg = "ERR_STORAGE_FAILURE Storage error";
        return r;
    }

    stat_out.assign(frame.payload.begin(), frame.payload.end());
    r.success = true;
    r.data = stat_out;
    return r;
}

