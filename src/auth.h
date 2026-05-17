#ifndef DOCUVAULT_AUTH_H
#define DOCUVAULT_AUTH_H

#include <string>
#include <unordered_map>

// ---------------------------------------------------------------------------
// User — a single registered user
// ---------------------------------------------------------------------------

struct User {
    std::string username;
    std::string password_hash;   // SHA-256 hex digest
};

// ---------------------------------------------------------------------------
// AuthManager — loads users from a flat file and authenticates sessions
//
// The user file format is one entry per line:
//     username:sha256_hex_hash
//
// Lines that are empty or start with '#' are ignored.
// ---------------------------------------------------------------------------

class AuthManager {
public:
    // Construct and load users from `user_file_path`.
    // Throws std::runtime_error if the file cannot be opened.
    explicit AuthManager(const std::string& user_file_path);

    // Authenticate a user by plaintext password.
    // Returns true if `username` exists and SHA-256(password) matches
    // the stored hash.
    bool authenticate(const std::string& username,
                      const std::string& password) const;

    // Return true if `username` is a registered user.
    bool userExists(const std::string& username) const;

    // Compute the SHA-256 hex digest of `input`.
    // This is a pure function with no dependency on instance state.
    static std::string hashPassword(const std::string& input);

private:
    // Read the user file and populate users_.
    void loadUsers(const std::string& path);

    std::unordered_map<std::string, User> users_;
};

#endif // DOCUVAULT_AUTH_H
