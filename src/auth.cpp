#include "auth.h"

/*
 * auth.cpp
 *
 * This file handles user management and credential verification.
 * Public API (AuthManager):
 *  - AuthManager(path): Constructor that initializes the manager and
 *      triggers loading of users from the specified file.
 *  - loadUsers(path): Opens the user file, parses username:hash lines,
 *      and populates the internal map while ignoring comments/malformed lines.
 *  - authenticate(username, password): Verifies a user by hashing the
 *      provided plaintext password and comparing to stored hash.
 *  - userExists(username): Checks if a username is present in the database.
 *  - hashPassword(input): Static helper computing SHA-256 hex digest
 *      using OpenSSL.
 */

#include <fstream>
#include <iomanip>
#include <iostream>
#include <openssl/sha.h>
#include <sstream>
#include <stdexcept>

// AuthManager(user_file_path): Construct and immediately load
// users from the provided file into memory.
AuthManager::AuthManager(const std::string& user_file_path)
{
    loadUsers(user_file_path);
}

// loadUsers(path): Parse the users file and populate the internal
// parses username:hash entries, skipping comments (lines starting with '#') and
// user map with username:hash entries, skipping comments/malformed lines.
void AuthManager::loadUsers(const std::string& path)
{
    std::ifstream in(path);
    if (!in) {
        throw std::runtime_error("Could not open users file: " + path);
    }

    users_.clear();

    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        if (!line.empty() && line[0] == '#') continue;

        const size_t first = line.find(':');
        if (first == std::string::npos) continue;
        const size_t second = line.find(':', first + 1);
        if (second != std::string::npos) {
            std::cerr << "WARN: malformed users line (multiple ':'): " << line << std::endl;
            continue;
        }

        std::string username = line.substr(0, first);
        std::string hash     = line.substr(first + 1);

        if (username.empty() || hash.empty()) continue;

        users_[username] = User{username, hash};
    }

    std::cout << "Loaded " << users_.size() << " users" << std::endl;
}

// authenticate(username, password): Compares the provided plaintext
// password (after SHA-256 hashing) with the stored hash and returns
// true if they match, granting access to the Coordinator.
bool AuthManager::authenticate(const std::string& username,
                               const std::string& password) const
{
    auto it = users_.find(username);
    if (it == users_.end()) return false;

    const std::string computed = hashPassword(password);
    return computed == it->second.password_hash;
}

// userExists(username): Returns true if the user is present in the
// loaded users database.
bool AuthManager::userExists(const std::string& username) const
{
    return users_.find(username) != users_.end();
}

// hashPassword(input): Compute SHA-256 hex digest of the input string
// and return it as a lowercase hex string.
std::string AuthManager::hashPassword(const std::string& input)
{
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.data()),
           input.size(),
           digest);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char b : digest) {
        oss << std::setw(2) << static_cast<int>(b);
    }
    return oss.str();
}

