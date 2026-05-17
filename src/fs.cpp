#include "fs.h"

/*
 * fs.cpp
 *
 * Implements the on-disk block storage and metadata index used by
 * storage nodes. Key components:
 *  - WriteBuffer: in-memory buffer that accumulates write data until
 *      BLOCK_SIZE and then flushes to blocks.
 *    - append / clear / isFull / hasData
 *  - FileSystem: manages base directory, index.dat, block bitmap and
 *      provides high-level file operations:
 *    - FileSystem(path): constructor that sets up base directory and
 *         initializes the block bitmap and index.
 *    - init(): create base dirs and load or create index.dat.
 *    - createDirectory / listDirectory
 *    - writeFile: allocate blocks, buffer, and update index metadata.
 *    - readFile / deleteFile
 *    - getStat / pathExists / checkPermission
 *    - flushBuffer: force buffered data to physical blocks.
 *    - saveIndex / loadIndex: serialize/deserialize index.dat.
 *    - allocateBlocks / freeBlocks / writeBlock / readBlock: low-level
 *      block operations.
 */

#include <algorithm>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <filesystem>

// append(data,len): Append up to `len` bytes into the write buffer,
// returning the number of bytes actually accepted (may be less).
size_t WriteBuffer::append(const char* data, size_t len)
{
    if (len == 0) return 0;
    if (data_.size() >= BUFFER_CAP) return 0;

    const size_t avail = BUFFER_CAP - data_.size();
    const size_t to_append = std::min(len, avail);
    data_.insert(data_.end(), data, data + to_append);
    return to_append;
}

// clear(): Reset the in-memory buffer and clear its target path.
void WriteBuffer::clear()
{
    data_.clear();
    target_path_.clear();
}

// FileSystem(base_path): Initialize the filesystem rooted at
// `base_path`, create directories and load index if present.
FileSystem::FileSystem(const std::string& base_path)
    : base_path_(base_path),
      block_bitmap_(MAX_BLOCKS, false)
{
    init();
}

// init(): Ensure base directories exist and load or create an empty
// index.dat representing the filesystem state.
void FileSystem::init()
{
    std::filesystem::create_directories(base_path_);
    std::filesystem::create_directories(base_path_ + "/blocks");

    const std::string index_path = base_path_ + "/index.dat";

    index_.clear();
    block_bitmap_.assign(MAX_BLOCKS, false);
    write_buffer_.clear();

    if (std::filesystem::exists(index_path)) {
        loadIndex();
        return;
    }

    FileMetadata root;
    root.name     = "/";
    root.path     = "/";
    root.owner    = "admin";
    root.size     = 0;
    root.perms    = DEFAULT_DIR_PERMS;
    root.created  = std::time(nullptr);
    root.modified = root.created;
    root.is_dir   = true;
    root.blocks.clear();

    index_[root.path] = std::move(root);
    saveIndex();
}


// createDirectory(path,owner): Create a new directory entry owned by
// `owner`; returns false if parent does not exist or path exists.
bool FileSystem::createDirectory(const std::string& path,
                                 const std::string& owner)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);

    if (index_.find(path) != index_.end()) return false;

    const std::string parent = parentPath(path);
    auto parentIt = index_.find(parent);
    if (parentIt == index_.end() || !parentIt->second.is_dir) return false;

    FileMetadata meta;
    meta.name     = baseName(path);
    meta.path     = path;
    meta.owner    = owner;
    meta.size     = 0;
    meta.perms    = DEFAULT_DIR_PERMS;
    meta.created  = std::time(nullptr);
    meta.modified = meta.created;
    meta.is_dir   = true;
    meta.blocks.clear();

    index_[path] = std::move(meta);
    saveIndex();
    return true;
}


// listDirectory(path): Return a sorted list of immediate entries
// contained in the directory at `path`.
std::vector<FileMetadata> FileSystem::listDirectory(const std::string& path) const
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);

    auto it = index_.find(path);
    if (it == index_.end() || !it->second.is_dir) {
        throw std::runtime_error("Not a directory: " + path);
    }

    std::vector<FileMetadata> result;
    for (const auto& kv : index_) {
        const auto& entry = kv.second;
        if (entry.path == path) continue;
        if (parentPath(entry.path) == path) {
            result.push_back(entry);
        }
    }

    std::sort(result.begin(), result.end(),
              [](const FileMetadata& a, const FileMetadata& b) {
                  return a.name < b.name;
              });
    return result;
}


// writeFile(path,data,owner): Write `data` to `path`, allocating blocks
// and updating index metadata; uses an in-memory buffer for partial
// block writes and persists the index on completion.
bool FileSystem::writeFile(const std::string& path, const std::string& data, const std::string& owner) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);

    if (write_buffer_.hasData()) {
        if (write_buffer_.targetPath() != path) {
            flushBuffer();
        } else {
            write_buffer_.clear();
        }
    }

    const std::time_t now = std::time(nullptr);
    auto it = index_.find(path);

    if (it != index_.end()) {
        if (it->second.is_dir) return false;
        freeBlocks(it->second.blocks);
        it->second.blocks.clear();

        it->second.size = data.size();
        it->second.modified = now;
    } else {
        const std::string parent = parentPath(path);
        auto parentIt = index_.find(parent);
        if (parentIt == index_.end() || !parentIt->second.is_dir) return false;

        FileMetadata meta;
        meta.name = baseName(path);
        meta.path = path;
        meta.owner = owner;
        meta.size = data.size();
        meta.perms = DEFAULT_FILE_PERMS;
        meta.created = now;
        meta.modified = now;
        meta.is_dir = false;
        meta.blocks.clear();

        index_[path] = std::move(meta);
    }

    if (!data.empty()) {
        const int required_blocks =
            static_cast<int>((data.size() + BLOCK_SIZE - 1) / BLOCK_SIZE);
        int free_cnt = 0;
        for (bool used : block_bitmap_) {
            if (!used) ++free_cnt;
        }
        if (required_blocks > free_cnt) {
            return false;
        }
    }

    if (!data.empty()) write_buffer_.setTargetPath(path);

    size_t offset = 0;
    while (offset < data.size()) {
        size_t accepted = write_buffer_.append(data.data() + offset,
                                               data.size() - offset);
        offset += accepted;

        if (write_buffer_.isFull()) {
            flushBuffer();
            write_buffer_.setTargetPath(path);
        }
    }

    auto& meta = index_.at(path);
    meta.size = data.size();
    meta.modified = now;
    saveIndex();

    if (!write_buffer_.hasData()) {
        write_buffer_.clear();
    }
    return true;
}


// readFile(path,data_out): Read file contents by concatenating the
// underlying blocks; returns false if path missing or is a directory.
bool FileSystem::readFile(const std::string& path, std::string& data_out)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);

    if (write_buffer_.hasData() && write_buffer_.targetPath() == path) {
        flushBuffer();
    }

    auto it = index_.find(path);
    if (it == index_.end() || it->second.is_dir) return false;

    const FileMetadata& meta = it->second;
    data_out.clear();
    data_out.reserve(meta.size);

    std::vector<char> buf(BLOCK_SIZE);
    for (int block_id : meta.blocks) {
        size_t n = readBlock(block_id, buf.data(), buf.size());
        if (n > 0) {
            data_out.append(buf.data(), n);
        }
    }

    if (data_out.size() > meta.size) {
        data_out.resize(meta.size);
    }
    return true;
}


// deleteFile(path): Remove file metadata and free its allocated blocks.
bool FileSystem::deleteFile(const std::string& path)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);

    auto it = index_.find(path);
    if (it == index_.end() || it->second.is_dir) return false;

    freeBlocks(it->second.blocks);
    it->second.blocks.clear();
    index_.erase(it);

    if (write_buffer_.hasData() && write_buffer_.targetPath() == path) {
        write_buffer_.clear();
    }

    saveIndex();
    return true;
}


// getStat(path): Return a copy of the FileMetadata for `path`.
FileMetadata FileSystem::getStat(const std::string& path) const
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    return index_.at(path);
}
// pathExists(path): Return true if `path` exists in the index.
bool FileSystem::pathExists(const std::string& path) const
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    return index_.find(path) != index_.end();
}

// checkPermission(path,username,perm): Verify whether `username` has
// the requested permission on `path` (owner bypasses checks).
bool FileSystem::checkPermission(const std::string& path,
                                 const std::string& username,
                                 PermType perm) const
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);

    auto it = index_.find(path);
    if (it == index_.end()) {
        throw std::out_of_range("Path not found: " + path);
    }

    const FileMetadata& meta = it->second;
    if (meta.owner == username) return true;

    uint16_t other_field = meta.perms & 0b111;
    return (other_field & static_cast<uint16_t>(perm)) != 0;
}

// flushBuffer(): Physically writes the current WriteBuffer contents to
// disk blocks, updates the target file's metadata (block list and
// modified time), and persists the index so the write becomes durable.
void FileSystem::flushBuffer()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);

    if (!write_buffer_.hasData()) return;

    const std::string target_path = write_buffer_.targetPath();
    auto it = index_.find(target_path);
    if (it == index_.end() || it->second.is_dir) {
        write_buffer_.clear();
        return;
    }

    const auto& buf = write_buffer_.data();
    const size_t buf_size = buf.size();
    if (buf_size == 0) {
        write_buffer_.clear();
        return;
    }

    const int blocks_needed =
        static_cast<int>((buf_size + BLOCK_SIZE - 1) / BLOCK_SIZE);

    std::vector<int> block_ids = allocateBlocks(blocks_needed);
    if (block_ids.empty()) {
        std::cerr << "ERR_DISK_FULL Could not allocate blocks for "
                  << target_path << std::endl;
        return;
    }

    size_t offset = 0;
    for (int block_id : block_ids) {
        const size_t len =
            std::min(static_cast<size_t>(BLOCK_SIZE), buf_size - offset);
        if (len > 0) {
            writeBlock(block_id, buf.data() + offset, len);
        }
        it->second.blocks.push_back(block_id);
        offset += len;
    }

    it->second.modified = std::time(nullptr);
    write_buffer_.clear();
    saveIndex();
}

// freeBlockCount(): Count and return the number of free blocks in the
// block bitmap.
int FileSystem::freeBlockCount() const
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    int free_cnt = 0;
    for (bool used : block_bitmap_) {
        if (!used) ++free_cnt;
    }
    return free_cnt;
}
// saveIndex(): Serialize the in-memory index and block mappings into
// `index.dat` on disk so filesystem state is preserved across restarts.
void FileSystem::saveIndex() const
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);

    const std::string index_path = base_path_ + "/index.dat";
    std::ofstream out(index_path, std::ios::trunc);
    if (!out) {
        throw std::runtime_error("Failed to write index: " + index_path);
    }

    out << "DOCUVAULT_INDEX_V1\n";

    std::vector<std::string> keys;
    keys.reserve(index_.size());
    for (const auto& kv : index_) keys.push_back(kv.first);
    std::sort(keys.begin(), keys.end());

    for (const auto& k : keys) {
        const FileMetadata& meta = index_.at(k);

        out << meta.path << "|"
            << (meta.is_dir ? 1 : 0) << "|"
            << meta.owner << "|"
            << meta.size << "|"
            << meta.perms << "|"
            << meta.created << "|"
            << meta.modified << "|";

        if (meta.is_dir || meta.blocks.empty()) {
            out << "-\n";
        } else {
            for (size_t i = 0; i < meta.blocks.size(); ++i) {
                if (i > 0) out << ",";
                out << meta.blocks[i];
            }
            out << "\n";
        }
    }
}

// loadIndex(): Read `index.dat` and reconstruct the in-memory index and
// the block bitmap; creates a root entry if missing.
void FileSystem::loadIndex()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);

    const std::string index_path = base_path_ + "/index.dat";
    std::ifstream in(index_path);
    if (!in) {
        throw std::runtime_error("Failed to open index: " + index_path);
    }

    index_.clear();
    block_bitmap_.assign(MAX_BLOCKS, false);
    write_buffer_.clear();

    std::string line;
    if (!std::getline(in, line)) {
        throw std::runtime_error("Index file is empty: " + index_path);
    }

    while (std::getline(in, line)) {
        if (line.empty()) continue;

        std::vector<std::string> parts;
        std::stringstream ss(line);
        std::string part;
        while (std::getline(ss, part, '|')) {
            parts.push_back(part);
        }
        if (parts.size() < 8) continue;

        FileMetadata meta;
        meta.path   = parts[0];
        meta.is_dir = (parts[1] == "1");
        meta.owner  = parts[2];
        meta.size   = static_cast<size_t>(std::stoull(parts[3]));
        meta.perms  = static_cast<uint16_t>(std::stoul(parts[4]));
        meta.created = static_cast<std::time_t>(std::stoll(parts[5]));
        meta.modified = static_cast<std::time_t>(std::stoll(parts[6]));
        meta.name   = baseName(meta.path);
        meta.blocks.clear();

        const std::string blocks_str = parts[7];
        if (!meta.is_dir && blocks_str != "-" && !blocks_str.empty()) {
            std::stringstream bs(blocks_str);
            std::string tok;
            while (std::getline(bs, tok, ',')) {
                if (tok.empty()) continue;
                int id = std::stoi(tok);
                if (id >= 0 && id < MAX_BLOCKS) {
                    meta.blocks.push_back(id);
                    block_bitmap_[id] = true;
                }
            }
        }

        index_[meta.path] = std::move(meta);
    }

    if (index_.find("/") == index_.end()) {
        FileMetadata root;
        root.name     = "/";
        root.path     = "/";
        root.owner    = "admin";
        root.size     = 0;
        root.perms    = DEFAULT_DIR_PERMS;
        root.created  = std::time(nullptr);
        root.modified = root.created;
        root.is_dir   = true;
        root.blocks.clear();
        index_[root.path] = root;
    }
}

// loadIndex(): Read `index.dat` and reconstruct the in-memory index and
// the block bitmap; creates a root entry if missing.

// allocateBlocks(num_blocks): Scan the block bitmap from the start and
// reserve the first `n` free blocks. Returns the allocated indices or
// an empty vector if not enough free blocks were available.
std::vector<int> FileSystem::allocateBlocks(int n)
{
    if (n <= 0) return {};

    std::vector<int> candidate;
    candidate.reserve(static_cast<size_t>(n));

    for (int i = 0; i < MAX_BLOCKS && static_cast<int>(candidate.size()) < n; ++i) {
        if (!block_bitmap_[i]) candidate.push_back(i);
    }

    if (static_cast<int>(candidate.size()) != n) return {};

    for (int id : candidate) block_bitmap_[id] = true;
    return candidate;
}


// freeBlocks(block_ids): Mark the listed block indices as free in the
// bitmap so they can be reused by future writes.
void FileSystem::freeBlocks(const std::vector<int>& block_ids)
{
    for (int id : block_ids) {
        if (id >= 0 && id < MAX_BLOCKS) {
            block_bitmap_[id] = false;
        }
    }
}


// writeBlock(block_id, data, len): Create or overwrite the on-disk
// block file under blocks/<id> with up to BLOCK_SIZE bytes of data.
void FileSystem::writeBlock(int block_id, const char* data, size_t len)
{
    std::filesystem::create_directories(base_path_ + "/blocks");
    const std::string path = base_path_ + "/blocks/" + std::to_string(block_id);
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        throw std::runtime_error("Failed to write block: " + path);
    }
    if (len > 0) {
        out.write(data, static_cast<std::streamsize>(len));
    }
}


// readBlock(block_id): Read raw bytes from the on-disk block file
// into `buf` and return the number of bytes actually read.
size_t FileSystem::readBlock(int block_id, char* buf, size_t buf_size) const
{
    const std::string path = base_path_ + "/blocks/" + std::to_string(block_id);
    std::ifstream in(path, std::ios::binary);
    if (!in) return 0;

    in.read(buf, static_cast<std::streamsize>(buf_size));

    return static_cast<size_t>(in.gcount());
}

// parentPath(path): Return the parent directory component of `path`.
std::string FileSystem::parentPath(const std::string& path)
{
    std::string p = path;
    while (p.size() > 1 && p.back() == '/') p.pop_back();

    if (p == "/") return "/";

    const size_t pos = p.find_last_of('/');
    if (pos == std::string::npos) return "/";
    if (pos == 0) return "/";
    return p.substr(0, pos);

}

// baseName(path): Return the last path component (filename) for `path`.
std::string FileSystem::baseName(const std::string& path)
{
    std::string p = path;
    while (p.size() > 1 && p.back() == '/') p.pop_back();

    if (p == "/") return "/";

    const size_t pos = p.find_last_of('/');
    if (pos == std::string::npos) return p;
    return p.substr(pos + 1);
}

