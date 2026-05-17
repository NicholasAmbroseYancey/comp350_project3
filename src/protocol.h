#ifndef DOCUVAULT_PROTOCOL_H
#define DOCUVAULT_PROTOCOL_H

// ===================================================================
// DocuVault Binary Message Protocol
//
// This header defines the wire format for Coordinator ↔ Storage
// communication.  You may ADD new message types or helper functions
// but must NOT remove or rename existing fields.
//
// DO NOT MODIFY existing definitions.
// ===================================================================

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// Magic number — identifies the start of a valid DocuVault frame.
// ASCII for "DVLT" in big-endian.
// ---------------------------------------------------------------------------

inline constexpr uint32_t PROTO_MAGIC = 0x44564C54;

// ---------------------------------------------------------------------------
// Message type codes
// ---------------------------------------------------------------------------
/*MSG_FORWARD_WRITE = 0x01 - Write/create a file
MSG_FORWARD_READ = 0x02 - Read a file
MSG_FORWARD_DELETE = 0x03 - Delete a file
MSG_FORWARD_LIST = 0x04 - List directory contents
MSG_FORWARD_MKDIR = 0x05 - Create a directory
MSG_FORWARD_STAT = 0x06 - Get file/directory metadata

MSG_ACK_OK = 0x10 - Success response
MSG_ACK_ERR = 0x11 - Error response

*/

enum MessageType : uint8_t {
    MSG_FORWARD_WRITE  = 0x01,
    MSG_FORWARD_READ   = 0x02,
    MSG_FORWARD_DELETE = 0x03,
    MSG_FORWARD_LIST   = 0x04,
    MSG_FORWARD_MKDIR  = 0x05,
    MSG_FORWARD_STAT   = 0x06,

    MSG_ACK_OK         = 0x10,
    MSG_ACK_ERR        = 0x11,
};

// ---------------------------------------------------------------------------
// HMAC-SHA256 tag size (32 bytes = 256 bits)
// ---------------------------------------------------------------------------

inline constexpr size_t HMAC_SIZE = 32;

// ---------------------------------------------------------------------------
// Wire format of a single message frame
//
//   Offset  Size    Field
//   ------  ------  -----
//   0       4       magic        (PROTO_MAGIC, network byte order)
//   4       1       msg_type     (one of the MessageType values)
//   5       4       payload_len  (network byte order)
//   9       N       payload      (N = payload_len bytes)
//   9+N     32      hmac         (HMAC-SHA256 computed over bytes 4..9+N,
//                                 i.e. msg_type + payload_len + payload)
//
//   Total frame size on the wire: 9 + N + 32 = 41 + N bytes
//
//   Header size (everything before the payload): 9 bytes
//   Signable region: bytes at offsets [4 .. 9+N) — type, length, payload
// ---------------------------------------------------------------------------

inline constexpr size_t FRAME_HEADER_SIZE = 9;   // magic(4) + type(1) + len(4)

struct MessageFrame {
    uint32_t     magic       = PROTO_MAGIC;
    MessageType  msg_type    = MSG_ACK_OK;
    uint32_t     payload_len = 0;
    std::vector<uint8_t> payload;
    uint8_t      hmac[HMAC_SIZE] = {};
};

// MessageFrame: in-memory representation of a protocol frame. Fields
// map directly to the wire layout documented above (magic, type,
// length, payload, hmac) so send/recv code can serialize/deserialize
// with minimal copying.

// ---------------------------------------------------------------------------
// Payload encoding helpers (optional — you may use your own scheme)
//
// These helpers use a simple format: fields are separated by a null
// byte ('\0').  The last field may contain arbitrary binary data
// (e.g. file contents).
//
// Example for FORWARD_WRITE:
//   field 0: path        "/docs/file.txt"
//   field 1: owner       "admin"
//   field 2: perms       "384"  (decimal representation of 0600)
//   field 3+: data       raw file bytes (rest of the payload)
// ---------------------------------------------------------------------------

// Pack string fields into a payload, separated by '\0'.
inline std::vector<uint8_t> packFields(
    const std::vector<std::string>& fields,
    const std::string& trailing_data = "")
{
    std::vector<uint8_t> payload;
    for (const auto& f : fields) {
        payload.insert(payload.end(), f.begin(), f.end());
        payload.push_back('\0');
    }
    if (!trailing_data.empty()) {
        payload.insert(payload.end(),
                       trailing_data.begin(), trailing_data.end());
    }
    return payload;
}

// Unpack the first `count` null-terminated fields from a payload.
// Returns false if the payload doesn't contain enough fields.
// Sets `data_offset` to the byte position where trailing data begins
// (i.e. right after the last '\0' of the extracted fields).
inline bool unpackFields(
    const std::vector<uint8_t>& payload,
    int count,
    std::vector<std::string>& fields,
    size_t& data_offset)
{
    fields.clear();
    size_t pos = 0;
    for (int i = 0; i < count; ++i) {
        size_t end = pos;
        while (end < payload.size() && payload[end] != '\0') ++end;
        if (end >= payload.size() && i < count - 1) return false;
        fields.emplace_back(payload.begin() + pos,
                            payload.begin() + end);
        pos = end + 1;  // skip the '\0'
    }
    data_offset = pos;
    return true;
}

#endif // DOCUVAULT_PROTOCOL_H
