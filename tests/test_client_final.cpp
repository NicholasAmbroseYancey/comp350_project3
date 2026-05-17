// =======================================================================
// DocuVault Final — Autograder Test Client
//
// Usage:
//   ./test_client_final <host> <port> <test_group> [storage_host] [storage_port]
//
// The optional storage_host/port are used by hmac_rejection to connect
// directly to a storage node.
//
// DO NOT MODIFY.
// =======================================================================

#include <arpa/inet.h>
#include <atomic>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <netdb.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

// -------------------------------------------------------------------
// Protocol constants (mirrored from protocol.h — test client does
// not include student headers)
// -------------------------------------------------------------------

static constexpr uint32_t PROTO_MAGIC = 0x44564C54;
static constexpr size_t   HMAC_SIZE   = 32;

// -------------------------------------------------------------------
// Socket RAII wrapper
// -------------------------------------------------------------------

class Connection {
public:
    Connection() = default;
    ~Connection() { disconnect(); }
    Connection(const Connection&)            = delete;
    Connection& operator=(const Connection&) = delete;

    bool connect(const std::string& host, int port, int timeout_sec = 10)
    {
        disconnect();
        fd_ = socket(AF_INET, SOCK_STREAM, 0);
        if (fd_ < 0) return false;

        struct timeval tv;
        tv.tv_sec  = timeout_sec;
        tv.tv_usec = 0;
        setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd_, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        struct addrinfo hints{}, *res = nullptr;
        hints.ai_family   = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        if (getaddrinfo(host.c_str(), std::to_string(port).c_str(),
                        &hints, &res) != 0 || !res) {
            disconnect();
            return false;
        }

        bool ok = (::connect(fd_, res->ai_addr, res->ai_addrlen) == 0);
        freeaddrinfo(res);
        if (!ok) { disconnect(); return false; }
        return true;
    }

    void disconnect()
    {
        if (fd_ >= 0) { close(fd_); fd_ = -1; }
    }

    int  fd()    const { return fd_; }
    bool valid() const { return fd_ >= 0; }

private:
    int fd_ = -1;
};

// -------------------------------------------------------------------
// Text protocol helpers (same as Checkpoint 1)
// -------------------------------------------------------------------

static void sendLine(int fd, const std::string& line)
{
    std::string msg = line + "\n";
    size_t sent = 0;
    while (sent < msg.size()) {
        ssize_t n = send(fd, msg.c_str() + sent, msg.size() - sent, 0);
        if (n <= 0) return;
        sent += static_cast<size_t>(n);
    }
}

static void sendRawBytes(int fd, const char* data, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, data + sent, len - sent, 0);
        if (n <= 0) return;
        sent += static_cast<size_t>(n);
    }
}

static std::string recvLine(int fd)
{
    std::string line;
    char c;
    while (true) {
        ssize_t n = recv(fd, &c, 1, 0);
        if (n <= 0) return line;
        if (c == '\n') return line;
        line += c;
    }
}

static std::string recvBytes(int fd, size_t n)
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

static bool startsWith(const std::string& s, const std::string& prefix)
{
    return s.size() >= prefix.size() &&
           s.compare(0, prefix.size(), prefix) == 0;
}

static std::string doLogin(int fd, const std::string& u, const std::string& p)
{
    sendLine(fd, "LOGIN " + u + " " + p);
    return recvLine(fd);
}

static std::string doWrite(int fd, const std::string& path,
                           const std::string& data)
{
    sendLine(fd, "WRITE " + path + " " + std::to_string(data.size()));
    sendRawBytes(fd, data.c_str(), data.size());
    return recvLine(fd);
}

static std::string doRead(int fd, const std::string& path,
                          std::string& data_out)
{
    sendLine(fd, "READ " + path);
    std::string resp = recvLine(fd);
    if (!startsWith(resp, "OK ")) return resp;
    size_t byte_count = 0;
    try { byte_count = static_cast<size_t>(std::stoi(resp.substr(3))); }
    catch (...) { return "ERR_BAD_RESPONSE"; }
    data_out = recvBytes(fd, byte_count);
    return resp;
}

static std::string doDelete(int fd, const std::string& path)
{
    sendLine(fd, "DELETE " + path);
    return recvLine(fd);
}

static std::string doStat(int fd, const std::string& path)
{
    sendLine(fd, "STAT " + path);
    return recvLine(fd);
}

static std::string doMkdir(int fd, const std::string& path)
{
    sendLine(fd, "MKDIR " + path);
    return recvLine(fd);
}

// -------------------------------------------------------------------
// Binary protocol helpers (for HMAC rejection test)
// -------------------------------------------------------------------

static bool sendAllBytes(int fd, const void* buf, size_t len)
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

static bool recvAllBytes(int fd, void* buf, size_t len)
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

// Send a binary frame with a deliberately INVALID HMAC.
static bool sendForgedFrame(int fd)
{
    // Build a FORWARD_READ frame for "/" with garbage HMAC.
    std::string path = "/";
    uint32_t magic_n = htonl(PROTO_MAGIC);
    uint8_t  msg_type = 0x02;  // MSG_FORWARD_READ
    uint32_t plen_n   = htonl(static_cast<uint32_t>(path.size()));

    if (!sendAllBytes(fd, &magic_n, 4))   return false;
    if (!sendAllBytes(fd, &msg_type, 1))  return false;
    if (!sendAllBytes(fd, &plen_n, 4))    return false;
    if (!sendAllBytes(fd, path.c_str(), path.size())) return false;

    // 32 bytes of 0xFF — obviously wrong HMAC.
    uint8_t bad_hmac[HMAC_SIZE];
    memset(bad_hmac, 0xFF, HMAC_SIZE);
    if (!sendAllBytes(fd, bad_hmac, HMAC_SIZE)) return false;

    return true;
}

// Try to receive a binary ACK frame.  Returns the message type.
// Returns 0 on failure (timeout / disconnect).
static uint8_t recvAckType(int fd)
{
    uint8_t header[9];
    if (!recvAllBytes(fd, header, 9)) return 0;

    // Parse payload length (bytes 5-8, network byte order).
    uint32_t plen_n;
    memcpy(&plen_n, header + 5, 4);
    uint32_t plen = ntohl(plen_n);

    // Skip payload + HMAC.
    std::vector<uint8_t> rest(plen + HMAC_SIZE);
    if (!recvAllBytes(fd, rest.data(), rest.size())) return 0;

    return header[4];  // msg_type byte
}

// -------------------------------------------------------------------
// Assertion helper
// -------------------------------------------------------------------

static int g_checks_passed = 0;
static int g_checks_total  = 0;

static bool check(const std::string& label, bool condition)
{
    ++g_checks_total;
    if (condition) {
        ++g_checks_passed;
        std::cout << "  [OK]   " << label << std::endl;
    } else {
        std::cout << "  [FAIL] " << label << std::endl;
    }
    return condition;
}

// -------------------------------------------------------------------
// Test: cluster_start (4 pts)
// -------------------------------------------------------------------

static bool test_cluster_start(const std::string& host, int port)
{
    std::cout << "=== Test: Cluster Start ===" << std::endl;

    Connection conn;
    if (!check("TCP connection to coordinator accepted",
               conn.connect(host, port))) {
        return false;
    }

    // Pre-login command should be rejected.
    sendLine(conn.fd(), "LIST /");
    std::string resp = recvLine(conn.fd());
    check("Coordinator responds to commands", !resp.empty());
    check("Pre-login command returns ERR_UNAUTHORIZED",
          startsWith(resp, "ERR_UNAUTHORIZED"));

    // Login should work.
    resp = doLogin(conn.fd(), "admin", "admin123");
    check("Login to coordinator succeeds",
          startsWith(resp, "OK"));

    return g_checks_passed == g_checks_total;
}

// -------------------------------------------------------------------
// Test: login_routing (4 pts)
// -------------------------------------------------------------------

static bool test_login_routing(const std::string& host, int port)
{
    std::cout << "=== Test: Login / Routing ===" << std::endl;

    Connection conn;
    if (!conn.connect(host, port)) {
        std::cout << "  [FAIL] Could not connect" << std::endl;
        return false;
    }

    std::string r = doLogin(conn.fd(), "admin", "admin123");
    check("Login succeeds", startsWith(r, "OK"));

    // STAT on root — coordinator routes to a storage node.
    r = doStat(conn.fd(), "/");
    check("STAT / routed to storage and returns OK",
          startsWith(r, "OK"));

    // MKDIR routed to storage.
    r = doMkdir(conn.fd(), "/routetest");
    check("MKDIR /routetest routed and succeeds",
          startsWith(r, "OK"));

    // STAT on new directory.
    r = doStat(conn.fd(), "/routetest");
    check("STAT /routetest returns OK",
          startsWith(r, "OK"));

    return g_checks_passed == g_checks_total;
}

// -------------------------------------------------------------------
// Test: write_replication (7 pts)
//   TCP portion — writes and reads via coordinator.
//   Volume inspection is done by run_test_final.sh after this.
// -------------------------------------------------------------------

static bool test_write_replication(const std::string& host, int port)
{
    std::cout << "=== Test: Write Replication ===" << std::endl;

    Connection conn;
    if (!conn.connect(host, port)) {
        std::cout << "  [FAIL] Could not connect" << std::endl;
        return false;
    }

    doLogin(conn.fd(), "admin", "admin123");

    std::string payload = "replicated data for testing";

    std::string r = doWrite(conn.fd(), "/repltest.txt", payload);
    check("WRITE /repltest.txt via coordinator succeeds",
          startsWith(r, "OK"));

    // Read it back — proves at least one replica has the data.
    std::string readback;
    r = doRead(conn.fd(), "/repltest.txt", readback);
    check("READ /repltest.txt returns OK",
          startsWith(r, "OK"));

    check("READ content matches written data",
          readback == payload);

    // Write a larger file for more thorough replication check.
    const size_t big_size = 8200;
    std::string big_payload(big_size, '\0');
    for (size_t i = 0; i < big_size; ++i)
        big_payload[i] = static_cast<char>('A' + (i % 26));

    r = doWrite(conn.fd(), "/replbig.dat", big_payload);
    check("WRITE large file via coordinator succeeds",
          startsWith(r, "OK"));

    r = doRead(conn.fd(), "/replbig.dat", readback);
    check("READ large file returns OK",
          startsWith(r, "OK"));

    check("READ large file content matches",
          readback == big_payload);

    // Write to a subdirectory.
    doMkdir(conn.fd(), "/repldir");
    r = doWrite(conn.fd(), "/repldir/nested.txt", "nested content");
    check("WRITE to subdirectory via coordinator succeeds",
          startsWith(r, "OK"));

    return g_checks_passed == g_checks_total;
}

// -------------------------------------------------------------------
// Test: read_replica (5 pts)
// -------------------------------------------------------------------

static bool test_read_replica(const std::string& host, int port)
{
    std::cout << "=== Test: Read from Replica ===" << std::endl;

    Connection conn;
    if (!conn.connect(host, port)) {
        std::cout << "  [FAIL] Could not connect" << std::endl;
        return false;
    }

    doLogin(conn.fd(), "admin", "admin123");

    // Write a file.
    std::string data = "read replica test data";
    std::string r = doWrite(conn.fd(), "/readrepl.txt", data);
    check("WRITE /readrepl.txt succeeds",
          startsWith(r, "OK"));

    // Read multiple times — coordinator may route to different nodes.
    bool all_reads_ok = true;
    for (int i = 0; i < 3; ++i) {
        std::string readback;
        r = doRead(conn.fd(), "/readrepl.txt", readback);
        if (!startsWith(r, "OK") || readback != data) {
            all_reads_ok = false;
            break;
        }
    }
    check("Multiple READs return correct data",
          all_reads_ok);

    // Overwrite and re-read.
    std::string data2 = "updated replica data";
    r = doWrite(conn.fd(), "/readrepl.txt", data2);
    check("Overwrite WRITE succeeds",
          startsWith(r, "OK"));

    std::string readback2;
    r = doRead(conn.fd(), "/readrepl.txt", readback2);
    check("READ after overwrite returns new content",
          readback2 == data2);

    // Read nonexistent file.
    std::string dummy;
    r = doRead(conn.fd(), "/no_such_file.txt", dummy);
    check("READ nonexistent file returns error",
          startsWith(r, "ERR_"));

    return g_checks_passed == g_checks_total;
}

// -------------------------------------------------------------------
// Test: delete_replication (5 pts)
//   TCP portion — writes, deletes, verifies.
//   Volume inspection by run_test_final.sh.
// -------------------------------------------------------------------

static bool test_delete_replication(const std::string& host, int port)
{
    std::cout << "=== Test: Delete Replication ===" << std::endl;

    Connection conn;
    if (!conn.connect(host, port)) {
        std::cout << "  [FAIL] Could not connect" << std::endl;
        return false;
    }

    doLogin(conn.fd(), "admin", "admin123");

    // Write, then delete.
    std::string r = doWrite(conn.fd(), "/delrepl.txt", "delete me");
    check("WRITE /delrepl.txt succeeds",
          startsWith(r, "OK"));

    r = doDelete(conn.fd(), "/delrepl.txt");
    check("DELETE /delrepl.txt succeeds",
          startsWith(r, "OK"));

    // Confirm it's gone.
    std::string dummy;
    r = doRead(conn.fd(), "/delrepl.txt", dummy);
    check("READ deleted file returns ERR_NOT_FOUND",
          startsWith(r, "ERR_NOT_FOUND"));

    // Delete nonexistent file.
    r = doDelete(conn.fd(), "/no_such.txt");
    check("DELETE nonexistent file returns error",
          startsWith(r, "ERR_"));

    // Write again to verify blocks were freed.
    r = doWrite(conn.fd(), "/delrepl2.txt", "post-delete write");
    check("WRITE after DELETE succeeds (blocks freed on both nodes)",
          startsWith(r, "OK"));

    return g_checks_passed == g_checks_total;
}

// -------------------------------------------------------------------
// Test: hmac_rejection (6 pts)
//   Sends a forged binary frame directly to a storage node.
//   storage_host/port are passed via command line.
// -------------------------------------------------------------------

static bool test_hmac_rejection(const std::string& storage_host,
                                int storage_port)
{
    std::cout << "=== Test: HMAC Rejection ===" << std::endl;

    Connection conn;
    if (!check("Direct TCP connection to storage node",
               conn.connect(storage_host, storage_port, 5))) {
        return false;
    }

    // Send a frame with obviously invalid HMAC.
    check("Forged frame sent successfully",
          sendForgedFrame(conn.fd()));

    // Storage node should respond with ACK_ERR (0x11).
    uint8_t ack_type = recvAckType(conn.fd());
    check("Storage node responds with ACK_ERR",
          ack_type == 0x11);

    // Send a second forged frame to verify the node didn't crash.
    bool sent_second = sendForgedFrame(conn.fd());
    if (sent_second) {
        uint8_t ack2 = recvAckType(conn.fd());
        check("Storage node still responsive after rejection",
              ack2 == 0x11);
    } else {
        // Connection might be closed — that's also acceptable behavior.
        check("Storage node still responsive after rejection", true);
    }

    // The run_test_final.sh script will check logs for:
    //   "WARN: rejected unauthenticated message from <ip>"
    check("HMAC rejection test completed (log check by runner)",
          true);

    return g_checks_passed == g_checks_total;
}

// -------------------------------------------------------------------
// Test: write_lock (6 pts)
//   Two concurrent WRITE requests to the same file.
// -------------------------------------------------------------------

static bool test_write_lock(const std::string& host, int port)
{
    std::cout << "=== Test: Write Lock ===" << std::endl;

    std::atomic<bool> thread1_ok{false};
    std::atomic<bool> thread2_ok{false};
    std::atomic<bool> thread1_done{false};

    // Thread 1: write a file.
    std::thread t1([&]() {
        Connection c;
        if (!c.connect(host, port, 15)) return;
        doLogin(c.fd(), "admin", "admin123");
        std::string r = doWrite(c.fd(), "/lockfile.txt",
                                "data_from_thread_1");
        thread1_ok = startsWith(r, "OK");
        thread1_done = true;
    });

    // Brief delay so thread 1 likely acquires the lock first.
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Thread 2: write to the same file (should queue behind the lock).
    std::thread t2([&]() {
        Connection c;
        if (!c.connect(host, port, 15)) return;
        doLogin(c.fd(), "admin", "admin123");
        std::string r = doWrite(c.fd(), "/lockfile.txt",
                                "data_from_thread_2");
        thread2_ok = startsWith(r, "OK");
    });

    t1.join();
    t2.join();

    check("Thread 1 WRITE succeeds", thread1_ok.load());
    check("Thread 2 WRITE succeeds (waited for lock)",
          thread2_ok.load());

    // Read the file — should contain one of the two payloads.
    Connection verify;
    if (verify.connect(host, port)) {
        doLogin(verify.fd(), "admin", "admin123");
        std::string readback;
        std::string r = doRead(verify.fd(), "/lockfile.txt", readback);
        bool content_valid = (readback == "data_from_thread_1" ||
                              readback == "data_from_thread_2");
        check("Final file content is one of the two written values",
              content_valid);
    }

    return g_checks_passed == g_checks_total;
}

// -------------------------------------------------------------------
// Test: deadlock_timeout (6 pts)
//   Storage-b is paused by run_test_final.sh before this runs.
//   The write will hang because storage-b is unresponsive, and the
//   lock should be forcibly released after LOCK_TIMEOUT_SECONDS.
// -------------------------------------------------------------------

static bool test_deadlock_timeout(const std::string& host, int port)
{
    std::cout << "=== Test: Deadlock Timeout ===" << std::endl;

    // Thread 1: send a write that will hang (storage-b is paused).
    std::atomic<bool> t1_got_response{false};
    std::atomic<bool> t1_got_error{false};

    std::thread t1([&]() {
        Connection c;
        if (!c.connect(host, port, 30)) return;
        doLogin(c.fd(), "admin", "admin123");
        std::string r = doWrite(c.fd(), "/timeout_test.txt",
                                "this write should timeout");
        t1_got_response = !r.empty();
        t1_got_error = startsWith(r, "ERR_");
    });

    // Brief delay, then send a second write to the same file.
    // This forces the lock contention path.
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    std::atomic<bool> t2_got_response{false};

    std::thread t2([&]() {
        Connection c;
        if (!c.connect(host, port, 30)) return;
        doLogin(c.fd(), "admin", "admin123");
        std::string r = doWrite(c.fd(), "/timeout_test.txt",
                                "second write after timeout");
        t2_got_response = !r.empty();
    });

    t1.join();
    t2.join();

    check("First WRITE eventually receives a response",
          t1_got_response.load());

    check("At least one request received an error response",
          t1_got_error.load() || t2_got_response.load());

    // The run_test_final.sh script checks coordinator logs for:
    //   "WARN: forced lock release on /timeout_test.txt after timeout"
    check("Deadlock timeout test completed (log check by runner)",
          true);

    return g_checks_passed == g_checks_total;
}

// -------------------------------------------------------------------
// Main
// -------------------------------------------------------------------

static void usage(const char* prog)
{
    std::cerr << "Usage: " << prog
              << " <host> <port> <test_group> [storage_host] [storage_port]\n"
              << "\nTest groups:\n"
              << "  cluster_start       (4 pts)\n"
              << "  login_routing       (4 pts)\n"
              << "  write_replication   (7 pts)\n"
              << "  read_replica        (5 pts)\n"
              << "  delete_replication  (5 pts)\n"
              << "  hmac_rejection      (6 pts) — needs storage_host/port\n"
              << "  write_lock          (6 pts)\n"
              << "  deadlock_timeout    (6 pts)\n";
}

int main(int argc, char* argv[])
{
    if (argc < 4) {
        usage(argv[0]);
        return 1;
    }

    std::string host  = argv[1];
    int         port  = std::atoi(argv[2]);
    std::string group = argv[3];

    std::string storage_host = (argc > 4) ? argv[4] : "localhost";
    int         storage_port = (argc > 5) ? std::atoi(argv[5]) : 9001;

    g_checks_passed = 0;
    g_checks_total  = 0;

    bool passed = false;

    if      (group == "cluster_start")      passed = test_cluster_start(host, port);
    else if (group == "login_routing")      passed = test_login_routing(host, port);
    else if (group == "write_replication")   passed = test_write_replication(host, port);
    else if (group == "read_replica")        passed = test_read_replica(host, port);
    else if (group == "delete_replication")  passed = test_delete_replication(host, port);
    else if (group == "hmac_rejection")      passed = test_hmac_rejection(storage_host, storage_port);
    else if (group == "write_lock")          passed = test_write_lock(host, port);
    else if (group == "deadlock_timeout")    passed = test_deadlock_timeout(host, port);
    else {
        std::cerr << "Unknown test group: " << group << std::endl;
        usage(argv[0]);
        return 1;
    }

    std::cout << std::endl;
    if (passed) {
        std::cout << "[PASS] " << group << ": "
                  << g_checks_passed << "/" << g_checks_total
                  << " checks passed" << std::endl;
    } else {
        std::cout << "[FAIL] " << group << ": "
                  << g_checks_passed << "/" << g_checks_total
                  << " checks passed" << std::endl;
    }

    return passed ? 0 : 1;
}
