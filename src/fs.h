#ifndef DOCUVAULT_FS_H
#define DOCUVAULT_FS_H

#include <cstdint>
#include <ctime>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

inline constexpr int    BLOCK_SIZE  = 4096;   // bytes per disk block
inline constexpr int    MAX_BLOCKS  = 1024;   // total blocks in the store
inline constexpr size_t BUFFER_CAP  = 4096;   // write-buffer capacity (bytes)

// Default permission bits (Unix rwx style, 9-bit):
//   owner: rw-  group: ---  other: ---   →  0600 for files
//   owner: rwx  group: ---  other: ---   →  0700 for directories
inline constexpr uint16_t DEFAULT_FILE_PERMS = 0600;
inline constexpr uint16_t DEFAULT_DIR_PERMS  = 0700;

// Permission bit masks used by checkPermission().
enum PermType : uint8_t {
    PERM_READ    = 4,   // r bit
    PERM_WRITE   = 2,   // w bit
    PERM_EXECUTE = 1    // x bit
};

// ---------------------------------------------------------------------------
// FileMetadata — one entry per file or directory in the index
// ---------------------------------------------------------------------------

struct FileMetadata {
    std::string         name;       // base name (e.g. "report.txt")
    std::string         path;       // full path  (e.g. "/docs/report.txt")
    std::string         owner;      // username that created this entry
    size_t              size = 0;   // file size in bytes (0 for directories)
    uint16_t            perms = 0;  // 9-bit Unix rwx (owner | group | other)
    std::time_t         created  = 0;
    std::time_t         modified = 0;
    bool                is_dir   = false;
    std::vector<int>    blocks;     // indices into the block store (files only)
};

// ---------------------------------------------------------------------------
// WriteBuffer — fixed-capacity in-memory buffer for incoming writes
// ---------------------------------------------------------------------------

class WriteBuffer {
public:
    WriteBuffer() = default;

    size_t append(const char* data, size_t len);
    void clear();

    bool   isFull()  const { return data_.size() >= BUFFER_CAP; }
    bool   hasData() const { return !data_.empty(); }
    size_t size()    const { return data_.size(); }

    const std::vector<char>& data() const { return data_; }

    void               setTargetPath(const std::string& p) { target_path_ = p; }
    const std::string& targetPath()  const                 { return target_path_; }

private:
    std::vector<char> data_;
    std::string       target_path_;
};

// ---------------------------------------------------------------------------
// FileSystem — manages the on-disk block store, metadata index, and buffering
// ---------------------------------------------------------------------------

class FileSystem {
public:
    explicit FileSystem(const std::string& base_path);

    bool createDirectory(const std::string& path, const std::string& owner);
    std::vector<FileMetadata> listDirectory(const std::string& path) const;

    bool writeFile(const std::string& path,
                   const std::string& data,
                   const std::string& owner);

    bool readFile(const std::string& path, std::string& data_out);
    bool deleteFile(const std::string& path);

    FileMetadata getStat(const std::string& path) const;
    bool pathExists(const std::string& path) const;

    bool checkPermission(const std::string& path,
                         const std::string& username,
                         PermType perm) const;

    void flushBuffer();

    WriteBuffer&       writeBuffer()       { return write_buffer_; }
    const WriteBuffer& writeBuffer() const { return write_buffer_; }

    int freeBlockCount() const;

private:
    void init();
    void saveIndex() const;
    void loadIndex();
    std::vector<int> allocateBlocks(int n);
    void freeBlocks(const std::vector<int>& block_ids);
    void writeBlock(int block_id, const char* data, size_t len);
    size_t readBlock(int block_id, char* buf, size_t buf_size) const;

    static std::string parentPath(const std::string& path);
    static std::string baseName(const std::string& path);

    std::string                                  base_path_;
    std::unordered_map<std::string, FileMetadata> index_;
    std::vector<bool>                            block_bitmap_;   // true = in use
    WriteBuffer                                  write_buffer_;
    mutable std::recursive_mutex                 mutex_;
};

#endif // DOCUVAULT_FS_H
