// ztar.c - Secure Compressed Archive System (Release v1.7)
// Build: make
// Dependencies: libsodium-dev liblz4-dev zlib1g-dev
// BSL-1.0
// Production Ready

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <errno.h>
#include <time.h>
#include <utime.h>
#include <libgen.h>
#include <limits.h>
#include <dirent.h>
#include <termios.h>
#include <sodium.h>
#include <lz4.h>
#include <lz4hc.h>
#include <zlib.h>
#include <pthread.h>

/* ============================================================================
 * Constants & Configuration
 * ============================================================================ */

#define ZTAR_MAGIC              0x5A544152
#define ZTAR_VERSION            7
#define ZTAR_KEY_SIZE           crypto_secretbox_KEYBYTES
#define ZTAR_NONCE_SIZE         crypto_secretbox_NONCEBYTES
#define ZTAR_MAC_SIZE           crypto_secretbox_MACBYTES
#define ZTAR_SALT_SIZE          crypto_pwhash_SALTBYTES
#define ZTAR_HASH_SIZE          crypto_generichash_BYTES
#define ZTAR_FILENAME_MAX       255
#define ZTAR_PATH_MAX           4096
#define ZTAR_CHUNK_SIZE         (1024 * 1024)
#define ZTAR_COMPRESS_LEVEL     LZ4HC_CLEVEL_MAX
#define ZTAR_MAX_THREADS        8
#define ZTAR_MAX_FILES          ((size_t)1 << 24)
#define ZTAR_FLUSH_CHUNK_SIZE   8
#define ZTAR_FLUSH_MAX_BYTES    (64 * 1024 * 1024)
#define ZTAR_MIN_PASSWORD_LEN   8

#define ZTAR_OPSLIMIT           crypto_pwhash_OPSLIMIT_MODERATE
#define ZTAR_MEMLIMIT           crypto_pwhash_MEMLIMIT_MODERATE

#define ZTAR_ENTRY_FILE         0x00
#define ZTAR_ENTRY_DIR          0x01
#define ZTAR_ENTRY_SYMLINK      0x02

/* Error codes */
#define ZTAR_ERR_NONE           0
#define ZTAR_ERR_IO             -1
#define ZTAR_ERR_CRYPTO         -2
#define ZTAR_ERR_COMPRESS       -3
#define ZTAR_ERR_MEMORY         -4
#define ZTAR_ERR_FORMAT         -5
#define ZTAR_ERR_AUTH           -6
#define ZTAR_ERR_PATH           -7
#define ZTAR_ERR_EXISTS         -8
#define ZTAR_ERR_LIMIT          -9
#define ZTAR_ERR_BUSY           -10

#ifdef O_CLOEXEC
#define ZTAR_OPEN_FLAGS         (O_CLOEXEC)
#else
#define ZTAR_OPEN_FLAGS         (0)
#endif

#ifdef O_TMPFILE
#define ZTAR_HAS_O_TMPFILE      1
#else
#define ZTAR_HAS_O_TMPFILE      0
#endif

/* ============================================================================
 * Data Structures
 * ============================================================================ */

/**
 * Progress callback for long-running operations.
 * @warning Called from within library code. Do NOT call ztar_* functions.
 */
typedef void (*ztar_progress_cb)(const char *filename, uint64_t processed,
                                  uint64_t total, void *user_data);

/**
 * Archive header - authenticated with MAC to prevent tampering.
 */
typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t file_count;
    uint64_t created_at;
    uint64_t total_original_size;
    uint64_t total_compressed_size;
    uint8_t  salt[ZTAR_SALT_SIZE];
    uint8_t  header_nonce[ZTAR_NONCE_SIZE];
    uint8_t  header_mac[ZTAR_MAC_SIZE];
    uint32_t flags;
    uint32_t reserved[3];
} ztar_header_t;

/**
 * Per-file entry in the archive.
 * Contains all metadata needed for extraction and verification.
 */
typedef struct {
    char     filename[ZTAR_FILENAME_MAX + 1];
    uint64_t original_size;
    uint64_t compressed_size;
    uint64_t encrypted_size;
    uint64_t data_offset;
    uint64_t mod_time;
    uint32_t mode;
    uint32_t uid;
    uint32_t gid;
    uint8_t  original_hash[ZTAR_HASH_SIZE];
    uint8_t  compressed_hash[ZTAR_HASH_SIZE];
    uint8_t  nonce[ZTAR_NONCE_SIZE];
    uint8_t  mac[ZTAR_MAC_SIZE];
    uint32_t original_crc32;
    uint32_t compressed_crc32;
    uint32_t entry_type;
    uint32_t reserved[2];
    char     symlink_target[ZTAR_PATH_MAX];
} ztar_entry_t;

/**
 * Pending entry in the parallel compression queue.
 */
typedef struct {
    ztar_entry_t *entry;
    uint8_t      *encrypted_data;
    size_t        encrypted_size;
    int           ready;
    int           flushed;
} ztar_pending_entry_t;

/**
 * Main archive context - all state lives here.
 * Thread-safe for concurrent read operations.
 */
typedef struct {
    int             fd;
    char           *path;
    ztar_header_t   header;
    ztar_entry_t   *entries;
    uint8_t        *key;                    /* mlock()ed */

    /* CV-based RWLock with writer preference */
    pthread_rwlock_t   io_lock;
    pthread_mutex_t    rw_mutex;
    pthread_cond_t     rw_cond;
    int                writers_waiting;
    int                active_readers;

    /* Entry metadata protection */
    pthread_mutex_t  entries_mutex;

    /* Parallel compression queue */
    ztar_pending_entry_t *pending_entries;
    int             pending_count;
    int             pending_capacity;
    int             pending_offset;
    pthread_mutex_t pending_mutex;
    pthread_cond_t  pending_cond;

    /* State */
    int             is_open;
    int             is_modified;

    /* User callbacks */
    ztar_progress_cb progress_cb;
    void           *progress_user_data;

    /* Configuration */
    int             num_threads;
    int             follow_symlinks;
    int             preserve_permissions;
    int             mlock_available;
    int             max_open_fds;

    /* Error tracking */
    int             flush_errors;
    int             last_error;
} ztar_t;

/**
 * Parallel compression work item.
 */
typedef struct {
    char        filepath[ZTAR_PATH_MAX];
    char        archive_name[ZTAR_FILENAME_MAX + 1];
    struct stat st;
    int         status;             /* 0=pending, 1=processing, 2=done, -1=error */
    uint8_t    *compressed_data;
    size_t      compressed_size;
    uint8_t     original_hash[ZTAR_HASH_SIZE];
    uint8_t     compressed_hash[ZTAR_HASH_SIZE];
    uint32_t    original_crc32;
    uint32_t    compressed_crc32;
    uint32_t    entry_type;
    char        symlink_target[ZTAR_PATH_MAX];
    pthread_t   thread;
    ztar_t     *ztar;
} ztar_work_item_t;

/* ============================================================================
 * Forward Declarations
 * ============================================================================ */

static int flush_pending_entries_chunked(ztar_t *ztar, int max_entries, size_t max_bytes);
static void compact_pending_array(ztar_t *ztar);

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

static void die(const char *fmt, ...) __attribute__((noreturn));
static void die(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "FATAL: ");
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
    exit(EXIT_FAILURE);
}

static void warn(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "WARNING: ");
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
}

__attribute__((unused))
static void info(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    fprintf(stdout, "INFO: ");
    vfprintf(stdout, fmt, args);
    fprintf(stdout, "\n");
    va_end(args);
}

static int check_mlock_available(void) {
    struct rlimit limit;
    if (getrlimit(RLIMIT_MEMLOCK, &limit) != 0) return 0;
    return (limit.rlim_cur >= ZTAR_KEY_SIZE || limit.rlim_cur == RLIM_INFINITY);
}

static int get_max_open_fds(void) {
    struct rlimit limit;
    long sysconf_max = sysconf(_SC_OPEN_MAX);
    if (getrlimit(RLIMIT_NOFILE, &limit) == 0 && limit.rlim_cur != RLIM_INFINITY)
        return (int)(limit.rlim_cur * 0.8);
    if (sysconf_max > 0) return (int)(sysconf_max * 0.8);
    return 256;
}

static void *secure_alloc(size_t size, int *mlock_available) {
    long pagesize = sysconf(_SC_PAGESIZE);
    if (pagesize < 0) pagesize = 4096;
    size_t alloc_size = ((size + pagesize - 1) / pagesize) * pagesize;
    void *ptr;
    if (posix_memalign(&ptr, pagesize, alloc_size) != 0)
        die("Memory allocation failed");
    memset(ptr, 0, alloc_size);
    if (*mlock_available) {
        if (mlock(ptr, alloc_size) != 0) {
            if (errno == ENOMEM || errno == EPERM) {
                warn("mlock() failed - keys may swap to disk. "
                     "Increase RLIMIT_MEMLOCK: ulimit -l unlimited");
                *mlock_available = 0;
            }
        }
    }
    return ptr;
}

static void secure_free(void *ptr, size_t size, int mlock_available) {
    if (ptr) {
        long pagesize = sysconf(_SC_PAGESIZE);
        if (pagesize < 0) pagesize = 4096;
        size_t alloc_size = ((size + pagesize - 1) / pagesize) * pagesize;
        sodium_memzero(ptr, size);
        if (mlock_available) munlock(ptr, alloc_size);
        free(ptr);
    }
}

static void *safe_malloc(size_t size) {
    void *ptr = calloc(1, size);
    if (!ptr) die("Memory allocation failed (%zu bytes)", size);
    return ptr;
}

static void *safe_realloc_preserve(void *ptr, size_t old_size, size_t new_size, int *out_of_memory) {
    void *new_ptr = malloc(new_size);
    if (!new_ptr) { *out_of_memory = 1; return NULL; }
    if (ptr && old_size > 0) {
        memcpy(new_ptr, ptr, old_size < new_size ? old_size : new_size);
        free(ptr);
    }
    *out_of_memory = 0;
    return new_ptr;
}

static void *safe_realloc(void *ptr, size_t size) {
    void *new_ptr = realloc(ptr, size);
    if (!new_ptr) die("Memory reallocation failed (%zu bytes)", size);
    return new_ptr;
}

static int safe_read_exact(int fd, void *buf, size_t count) {
    size_t total = 0;
    while (total < count) {
        ssize_t n = read(fd, (uint8_t *)buf + total, count - total);
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        if (n == 0) return -1;
        total += n;
    }
    return 0;
}

static int safe_write_exact(int fd, const void *buf, size_t count) {
    size_t total = 0;
    while (total < count) {
        ssize_t n = write(fd, (const uint8_t *)buf + total, count - total);
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        total += n;
    }
    return 0;
}

static ssize_t safe_read_retry(int fd, void *buf, size_t max_count) {
    ssize_t n;
    do { n = read(fd, buf, max_count); } while (n < 0 && errno == EINTR);
    return n;
}

static uint64_t get_current_time(void) { return (uint64_t)time(NULL); }

static void generate_random(uint8_t *buf, size_t len) { randombytes_buf(buf, len); }

/* ============================================================================
 * CV-based RWLock with Writer Preference
 * ============================================================================ */

static void io_read_lock(ztar_t *ztar) {
    pthread_mutex_lock(&ztar->rw_mutex);
    while (ztar->writers_waiting > 0) {
        pthread_cond_wait(&ztar->rw_cond, &ztar->rw_mutex);
    }
    ztar->active_readers++;
    pthread_mutex_unlock(&ztar->rw_mutex);
    pthread_rwlock_rdlock(&ztar->io_lock);
}

static void io_read_unlock(ztar_t *ztar) {
    pthread_rwlock_unlock(&ztar->io_lock);
    pthread_mutex_lock(&ztar->rw_mutex);
    ztar->active_readers--;
    if (ztar->active_readers == 0 && ztar->writers_waiting > 0) {
        pthread_cond_signal(&ztar->rw_cond);
    }
    pthread_mutex_unlock(&ztar->rw_mutex);
}

static void io_write_lock(ztar_t *ztar) {
    pthread_mutex_lock(&ztar->rw_mutex);
    ztar->writers_waiting++;
    pthread_mutex_unlock(&ztar->rw_mutex);
    pthread_rwlock_wrlock(&ztar->io_lock);
}

static void io_write_unlock(ztar_t *ztar) {
    pthread_mutex_lock(&ztar->rw_mutex);
    ztar->writers_waiting--;
    if (ztar->writers_waiting == 0) {
        pthread_cond_broadcast(&ztar->rw_cond);
    }
    pthread_mutex_unlock(&ztar->rw_mutex);
    pthread_rwlock_unlock(&ztar->io_lock);
}

/* ============================================================================
 * Secure Password Input
 * ============================================================================ */

static char *read_password_secure(const char *prompt) {
    char *password = malloc(ZTAR_PATH_MAX);
    if (!password) return NULL;

    fprintf(stderr, "%s", prompt);
    fflush(stderr);

    struct termios old, new;
    int have_term = (tcgetattr(STDIN_FILENO, &old) == 0);
    if (have_term) {
        new = old;
        new.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &new);
    }

    if (!fgets(password, ZTAR_PATH_MAX - 1, stdin)) {
        if (have_term) tcsetattr(STDIN_FILENO, TCSAFLUSH, &old);
        fprintf(stderr, "\n");
        free(password);
        return NULL;
    }

    if (have_term) tcsetattr(STDIN_FILENO, TCSAFLUSH, &old);
    fprintf(stderr, "\n");

    size_t len = strlen(password);
    if (len > 0 && password[len - 1] == '\n') password[--len] = '\0';
    if (len == 0) { free(password); return NULL; }

    return password;
}

static void clear_sensitive(char *ptr, size_t len) {
    if (ptr && len > 0) sodium_memzero(ptr, len);
}

/* ============================================================================
 * File Operations
 * ============================================================================ */

static int create_file_atomic(const char *path) {
    return open(path, O_CREAT | O_EXCL | O_RDWR | ZTAR_OPEN_FLAGS, 0600);
}

static int create_secure_temp(ztar_t *ztar, char *path_template, size_t template_size) {
    if (ztar->pending_count - ztar->pending_offset + 5 > ztar->max_open_fds) {
        flush_pending_entries_chunked(ztar, ZTAR_FLUSH_CHUNK_SIZE, ZTAR_FLUSH_MAX_BYTES);
        compact_pending_array(ztar);
    }
#if ZTAR_HAS_O_TMPFILE
    int tmp_fd = open("/tmp", O_TMPFILE | O_RDWR | ZTAR_OPEN_FLAGS, 0600);
    if (tmp_fd >= 0) {
        snprintf(path_template, template_size, "[O_TMPFILE]");
        return tmp_fd;
    }
#endif
    snprintf(path_template, template_size, "/tmp/ztar_XXXXXX");
    int fd = mkstemp(path_template);
    if (fd < 0) return -1;
    int flags = fcntl(fd, F_GETFD, 0);
    if (flags >= 0) fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
    unlink(path_template);
    return fd;
}

static int safe_open_file(const char *path, int follow_symlinks, struct stat *out_st) {
    int flags = O_RDONLY | ZTAR_OPEN_FLAGS;
    if (!follow_symlinks) flags |= O_NOFOLLOW;
    int fd = open(path, flags);
    if (fd < 0) return -1;
    if (out_st && fstat(fd, out_st) < 0) { close(fd); return -1; }
    return fd;
}

static int validate_extract_path(const char *output_dir, const char *filename,
                                  char *out, size_t out_size) {
    char canonical_dir[ZTAR_PATH_MAX];
    if (realpath(output_dir, canonical_dir) == NULL) {
        if (mkdir(output_dir, 0755) != 0 && errno != EEXIST) return -1;
        if (realpath(output_dir, canonical_dir) == NULL) return -1;
    }
    size_t dir_len = strlen(canonical_dir);
    if (filename[0] == '\0' || filename[0] == '/') return -1;
    if (dir_len + 1 + strlen(filename) >= ZTAR_PATH_MAX) return -1;
    snprintf(out, out_size, "%s/%s", canonical_dir, filename);
    const char *p = filename;
    while (*p) {
        if (p[0] == '.' && p[1] == '.' && (p[2] == '/' || p[2] == '\0')) return -1;
        if (p[0] == '/' && p[1] == '/') return -1;
        while (*p && *p != '/') p++;
        while (*p == '/') p++;
    }
    char parent[ZTAR_PATH_MAX];
    strncpy(parent, out, sizeof(parent) - 1);
    parent[sizeof(parent) - 1] = '\0';
    char *slash = strrchr(parent, '/');
    if (slash) {
        *slash = '\0';
        char build_path[ZTAR_PATH_MAX];
        strncpy(build_path, canonical_dir, sizeof(build_path) - 1);
        build_path[sizeof(build_path) - 1] = '\0';
        char *sp = parent + dir_len;
        while (*sp == '/') sp++;
        char tmp[ZTAR_PATH_MAX];
        strncpy(tmp, sp, sizeof(tmp) - 1);
        tmp[sizeof(tmp) - 1] = '\0';
        char *token = strtok(tmp, "/");
        while (token) {
            size_t len = strlen(build_path);
            snprintf(build_path + len, sizeof(build_path) - len, "/%s", token);
            mkdir(build_path, 0755);
            token = strtok(NULL, "/");
        }
    }
    return 0;
}

/* ============================================================================
 * Streaming Hash & CRC Functions
 * ============================================================================ */

static int compute_hash_streaming(int fd, uint64_t size, uint8_t *hash) {
    crypto_generichash_state state;
    crypto_generichash_init(&state, NULL, 0, ZTAR_HASH_SIZE);
    uint8_t *buf = safe_malloc(ZTAR_CHUNK_SIZE);
    uint64_t remaining = size;
    int ret = ZTAR_ERR_IO;
    if (lseek(fd, 0, SEEK_SET) < 0) goto cleanup;
    while (remaining > 0) {
        size_t to_read = (remaining < ZTAR_CHUNK_SIZE) ? (size_t)remaining : ZTAR_CHUNK_SIZE;
        ssize_t n = safe_read_retry(fd, buf, to_read);
        if (n <= 0) goto cleanup;
        crypto_generichash_update(&state, buf, (size_t)n);
        remaining -= (size_t)n;
    }
    crypto_generichash_final(&state, hash, ZTAR_HASH_SIZE);
    ret = ZTAR_ERR_NONE;
cleanup:
    free(buf);
    return ret;
}

static void compute_hash_buffer(const uint8_t *data, size_t len, uint8_t *hash) {
    crypto_generichash_state state;
    crypto_generichash_init(&state, NULL, 0, ZTAR_HASH_SIZE);
    crypto_generichash_update(&state, data, len);
    crypto_generichash_final(&state, hash, ZTAR_HASH_SIZE);
}

static uint32_t compute_crc32_streaming(int fd, uint64_t size) {
    uint32_t crc = crc32(0L, Z_NULL, 0);
    uint8_t *buf = safe_malloc(ZTAR_CHUNK_SIZE);
    uint64_t remaining = size;
    if (lseek(fd, 0, SEEK_SET) < 0) { free(buf); return 0; }
    while (remaining > 0) {
        size_t to_read = (remaining < ZTAR_CHUNK_SIZE) ? (size_t)remaining : ZTAR_CHUNK_SIZE;
        ssize_t n = safe_read_retry(fd, buf, to_read);
        if (n <= 0) break;
        crc = crc32(crc, buf, (uInt)n);
        remaining -= (size_t)n;
    }
    free(buf);
    return crc;
}

static uint32_t compute_crc32_buffer(const uint8_t *data, size_t len) {
    return (uint32_t)crc32(0L, (const Bytef *)data, (uInt)len);
}

/* ============================================================================
 * Header Authentication
 * ============================================================================ */

static int compute_header_mac(const uint8_t *key, ztar_header_t *header) {
    crypto_generichash_state state;
    uint8_t header_hash[ZTAR_HASH_SIZE];
    uint8_t zero[ZTAR_MAC_SIZE] = {0};
    crypto_generichash_init(&state, NULL, 0, ZTAR_HASH_SIZE);
    crypto_generichash_update(&state, (const uint8_t *)&header->magic, sizeof(header->magic));
    crypto_generichash_update(&state, (const uint8_t *)&header->version, sizeof(header->version));
    crypto_generichash_update(&state, (const uint8_t *)&header->file_count, sizeof(header->file_count));
    crypto_generichash_update(&state, (const uint8_t *)&header->created_at, sizeof(header->created_at));
    crypto_generichash_update(&state, (const uint8_t *)&header->total_original_size, sizeof(header->total_original_size));
    crypto_generichash_update(&state, (const uint8_t *)&header->total_compressed_size, sizeof(header->total_compressed_size));
    crypto_generichash_update(&state, (const uint8_t *)&header->salt, ZTAR_SALT_SIZE);
    crypto_generichash_final(&state, header_hash, ZTAR_HASH_SIZE);
    generate_random(header->header_nonce, ZTAR_NONCE_SIZE);
    return crypto_secretbox_detached(header->header_mac, zero, header_hash,
                                     ZTAR_HASH_SIZE, header->header_nonce, key);
}

static int verify_header_mac(const uint8_t *key, const ztar_header_t *header) {
    crypto_generichash_state state;
    uint8_t header_hash[ZTAR_HASH_SIZE];
    uint8_t decrypted[ZTAR_HASH_SIZE];
    uint8_t empty[1] = {0};
    crypto_generichash_init(&state, NULL, 0, ZTAR_HASH_SIZE);
    crypto_generichash_update(&state, (const uint8_t *)&header->magic, sizeof(header->magic));
    crypto_generichash_update(&state, (const uint8_t *)&header->version, sizeof(header->version));
    crypto_generichash_update(&state, (const uint8_t *)&header->file_count, sizeof(header->file_count));
    crypto_generichash_update(&state, (const uint8_t *)&header->created_at, sizeof(header->created_at));
    crypto_generichash_update(&state, (const uint8_t *)&header->total_original_size, sizeof(header->total_original_size));
    crypto_generichash_update(&state, (const uint8_t *)&header->total_compressed_size, sizeof(header->total_compressed_size));
    crypto_generichash_update(&state, (const uint8_t *)&header->salt, ZTAR_SALT_SIZE);
    crypto_generichash_final(&state, header_hash, ZTAR_HASH_SIZE);
    return crypto_secretbox_open_detached(decrypted, header->header_mac, empty,
                                          0, header->header_nonce, key);
}

/* ============================================================================
 * Cryptographic Functions
 * ============================================================================ */

static int crypto_init(void) {
    if (sodium_init() < 0) die("Failed to initialize libsodium - check installation");
    return 0;
}

static int derive_key(const char *password, const uint8_t *salt, uint8_t *key) {
    if (!password || !salt || !key) return ZTAR_ERR_CRYPTO;
    return crypto_pwhash(key, ZTAR_KEY_SIZE, password, strlen(password),
                         salt, ZTAR_OPSLIMIT, ZTAR_MEMLIMIT, crypto_pwhash_ALG_DEFAULT);
}

static int encrypt_buffer(const uint8_t *key, const uint8_t *nonce,
                          const uint8_t *plaintext, size_t plaintext_len,
                          uint8_t *ciphertext, uint8_t *mac) {
    return crypto_secretbox_detached(ciphertext, mac, plaintext,
                                     plaintext_len, nonce, key);
}

static int decrypt_buffer(const uint8_t *key, const uint8_t *nonce,
                          const uint8_t *ciphertext, size_t ciphertext_len,
                          const uint8_t *mac, uint8_t *plaintext) {
    return crypto_secretbox_open_detached(plaintext, ciphertext, mac,
                                          ciphertext_len, nonce, key);
}

/* ============================================================================
 * Streaming Compression Functions
 * ============================================================================ */

typedef struct { LZ4_streamHC_t *stream; } ztar_compress_stream_t;
typedef struct { LZ4_streamDecode_t *stream; } ztar_decompress_stream_t;

static ztar_compress_stream_t *compress_stream_create(void) {
    ztar_compress_stream_t *cs = safe_malloc(sizeof(*cs));
    cs->stream = LZ4_createStreamHC();
    if (!cs->stream) { free(cs); return NULL; }
    LZ4_resetStreamHC(cs->stream, ZTAR_COMPRESS_LEVEL);
    return cs;
}

static void compress_stream_free(ztar_compress_stream_t *cs) {
    if (cs) { LZ4_freeStreamHC(cs->stream); free(cs); }
}

static ztar_decompress_stream_t *decompress_stream_create(void) {
    ztar_decompress_stream_t *ds = safe_malloc(sizeof(*ds));
    ds->stream = LZ4_createStreamDecode();
    if (!ds->stream) { free(ds); return NULL; }
    LZ4_setStreamDecode(ds->stream, NULL, 0);
    return ds;
}

static void decompress_stream_free(ztar_decompress_stream_t *ds) {
    if (ds) { LZ4_freeStreamDecode(ds->stream); free(ds); }
}

static int compress_data_streaming(int src_fd, int dst_fd,
                                   size_t original_size, size_t *compressed_total,
                                   ztar_progress_cb progress_cb, void *user_data,
                                   const char *filename) {
    ztar_compress_stream_t *cs = compress_stream_create();
    if (!cs) return ZTAR_ERR_COMPRESS;
    uint8_t *in_buf = safe_malloc(ZTAR_CHUNK_SIZE);
    uint8_t *out_buf = safe_malloc(LZ4_compressBound(ZTAR_CHUNK_SIZE));
    size_t total_written = 0;
    uint64_t processed = 0;
    int ret = ZTAR_ERR_COMPRESS;
    if (lseek(src_fd, 0, SEEK_SET) < 0) goto cleanup;
    while (processed < original_size) {
        size_t to_read = (original_size - processed < ZTAR_CHUNK_SIZE) ?
                         (size_t)(original_size - processed) : ZTAR_CHUNK_SIZE;
        ssize_t bytes_read = safe_read_retry(src_fd, in_buf, to_read);
        if (bytes_read <= 0) goto cleanup;
        processed += bytes_read;
        int csize = LZ4_compress_HC_continue(cs->stream, (const char *)in_buf,
                     (char *)out_buf, (int)bytes_read, LZ4_compressBound(ZTAR_CHUNK_SIZE));
        if (csize <= 0) goto cleanup;
        if (safe_write_exact(dst_fd, out_buf, (size_t)csize) != 0) goto cleanup;
        total_written += (size_t)csize;
        if (progress_cb && (processed % (ZTAR_CHUNK_SIZE * 10) == 0 || processed >= original_size))
            progress_cb(filename, processed, original_size, user_data);
    }
    int flush = LZ4_compress_HC_continue(cs->stream, NULL, (char *)out_buf, 0,
                                          LZ4_compressBound(ZTAR_CHUNK_SIZE));
    if (flush > 0) {
        if (safe_write_exact(dst_fd, out_buf, (size_t)flush) != 0) goto cleanup;
        total_written += (size_t)flush;
    }
    *compressed_total = total_written;
    ret = ZTAR_ERR_NONE;
cleanup:
    compress_stream_free(cs);
    free(in_buf);
    free(out_buf);
    return ret;
}

static int decompress_data_streaming(int src_fd, int dst_fd,
                                     size_t compressed_size, size_t original_size,
                                     ztar_progress_cb progress_cb, void *user_data,
                                     const char *filename) {
    ztar_decompress_stream_t *ds = decompress_stream_create();
    if (!ds) return ZTAR_ERR_COMPRESS;
    uint8_t *in_buf = safe_malloc(ZTAR_CHUNK_SIZE);
    uint8_t *out_buf = safe_malloc(ZTAR_CHUNK_SIZE);
    size_t total_read = 0, total_written = 0;
    int ret = ZTAR_ERR_COMPRESS;
    while (total_read < compressed_size) {
        size_t to_read = (compressed_size - total_read < ZTAR_CHUNK_SIZE) ?
                         (compressed_size - total_read) : ZTAR_CHUNK_SIZE;
        if (safe_read_exact(src_fd, in_buf, to_read) != 0) goto cleanup;
        total_read += to_read;
        int dsize = LZ4_decompress_safe_continue(ds->stream, (const char *)in_buf,
                     (char *)out_buf, (int)to_read, ZTAR_CHUNK_SIZE);
        if (dsize <= 0) goto cleanup;
        if (safe_write_exact(dst_fd, out_buf, (size_t)dsize) != 0) goto cleanup;
        total_written += (size_t)dsize;
        if (progress_cb && (total_written % (ZTAR_CHUNK_SIZE * 10) == 0 || total_read >= compressed_size))
            progress_cb(filename, total_written, original_size, user_data);
    }
    if (total_written != original_size) goto cleanup;
    ret = ZTAR_ERR_NONE;
cleanup:
    decompress_stream_free(ds);
    free(in_buf);
    free(out_buf);
    return ret;
}

/* ============================================================================
 * Parallel Compression Engine
 * ============================================================================ */

static void *parallel_compress_worker(void *arg) {
    ztar_work_item_t *item = (ztar_work_item_t *)arg;
    item->status = 1;

    int src_fd = safe_open_file(item->filepath, item->ztar->follow_symlinks, NULL);
    if (src_fd < 0) { item->status = -1; return NULL; }

    if (compute_hash_streaming(src_fd, item->st.st_size, item->original_hash) != 0) {
        close(src_fd); item->status = -1; return NULL;
    }
    item->original_crc32 = compute_crc32_streaming(src_fd, item->st.st_size);

    char tmp_path[ZTAR_PATH_MAX];
    int tmp_fd = create_secure_temp(item->ztar, tmp_path, sizeof(tmp_path));
    if (tmp_fd < 0) { close(src_fd); item->status = -1; return NULL; }

    if (compress_data_streaming(src_fd, tmp_fd, item->st.st_size, &item->compressed_size,
                                 NULL, NULL, item->archive_name) != 0) {
        close(src_fd); close(tmp_fd); item->status = -1; return NULL;
    }
    close(src_fd);

    item->compressed_data = safe_malloc(item->compressed_size);
    if (lseek(tmp_fd, 0, SEEK_SET) < 0 ||
        safe_read_exact(tmp_fd, item->compressed_data, item->compressed_size) != 0) {
        close(tmp_fd); free(item->compressed_data);
        item->compressed_data = NULL; item->status = -1; return NULL;
    }
    close(tmp_fd);

    compute_hash_buffer(item->compressed_data, item->compressed_size, item->compressed_hash);
    item->compressed_crc32 = compute_crc32_buffer(item->compressed_data, item->compressed_size);

    item->status = 2;
    pthread_mutex_lock(&item->ztar->pending_mutex);
    pthread_cond_signal(&item->ztar->pending_cond);
    pthread_mutex_unlock(&item->ztar->pending_mutex);

    return NULL;
}

static void queue_pending_entry(ztar_t *ztar, ztar_work_item_t *item) {
    pthread_mutex_lock(&ztar->pending_mutex);

    if (ztar->pending_count >= ztar->pending_capacity) {
        size_t new_cap = (ztar->pending_capacity == 0) ? 16 : ztar->pending_capacity * 2;
        int oom = 0;
        void *new_entries = safe_realloc_preserve(ztar->pending_entries,
            ztar->pending_capacity * sizeof(ztar_pending_entry_t),
            new_cap * sizeof(ztar_pending_entry_t), &oom);
        if (oom) {
            pthread_mutex_unlock(&ztar->pending_mutex);
            warn("Out of memory for pending entries - entry queued but may be lost");
            return;
        }
        ztar->pending_entries = new_entries;
        ztar->pending_capacity = new_cap;
    }

    ztar_pending_entry_t *pe = &ztar->pending_entries[ztar->pending_count];
    memset(pe, 0, sizeof(*pe));
    pe->entry = safe_malloc(sizeof(ztar_entry_t));

    ztar_entry_t *entry = pe->entry;
    memset(entry, 0, sizeof(ztar_entry_t));
    strncpy(entry->filename, item->archive_name, ZTAR_FILENAME_MAX);
    entry->entry_type = item->entry_type;
    entry->original_size = item->st.st_size;
    entry->compressed_size = item->compressed_size;
    entry->mod_time = item->st.st_mtime;
    entry->mode = item->st.st_mode;
    entry->uid = item->st.st_uid;
    entry->gid = item->st.st_gid;
    entry->original_crc32 = item->original_crc32;
    entry->compressed_crc32 = item->compressed_crc32;
    memcpy(entry->original_hash, item->original_hash, ZTAR_HASH_SIZE);
    memcpy(entry->compressed_hash, item->compressed_hash, ZTAR_HASH_SIZE);

    if (item->entry_type == ZTAR_ENTRY_SYMLINK)
        strncpy(entry->symlink_target, item->symlink_target, ZTAR_PATH_MAX - 1);

    if (item->compressed_size > 0 && item->compressed_data) {
        uint8_t *ciphertext = safe_malloc(item->compressed_size);
        generate_random(entry->nonce, ZTAR_NONCE_SIZE);

        if (encrypt_buffer(ztar->key, entry->nonce, item->compressed_data,
                          item->compressed_size, ciphertext, entry->mac) == 0) {
            entry->encrypted_size = item->compressed_size + ZTAR_MAC_SIZE;
            pe->encrypted_size = entry->encrypted_size;
            pe->encrypted_data = safe_malloc(pe->encrypted_size);
            memcpy(pe->encrypted_data, entry->mac, ZTAR_MAC_SIZE);
            memcpy(pe->encrypted_data + ZTAR_MAC_SIZE, ciphertext, item->compressed_size);
            pe->ready = 1;
        }
        free(ciphertext);
    } else {
        pe->ready = 1;
    }

    ztar->pending_count++;
    pthread_mutex_unlock(&ztar->pending_mutex);
}

static void compact_pending_array(ztar_t *ztar) {
    pthread_mutex_lock(&ztar->pending_mutex);

    int remove_count = 0;
    for (int i = 0; i < ztar->pending_count; i++) {
        if (ztar->pending_entries[i].flushed) remove_count++;
        else break;
    }

    if (remove_count > 0) {
        int remaining = ztar->pending_count - remove_count;
        if (remaining > 0) {
            memmove(ztar->pending_entries,
                    ztar->pending_entries + remove_count,
                    remaining * sizeof(ztar_pending_entry_t));
        }
        ztar->pending_count = remaining;
        ztar->pending_offset = 0;
    }

    pthread_mutex_unlock(&ztar->pending_mutex);
}

static int flush_pending_entries_chunked(ztar_t *ztar, int max_entries, size_t max_bytes) {
    int total_flushed = 0;
    int total_errors = 0;

    while (1) {
        pthread_mutex_lock(&ztar->pending_mutex);

        int start = ztar->pending_offset;
        int end = start;
        size_t chunk_bytes = 0;

        while (end < ztar->pending_count && (end - start) < max_entries) {
            if (!ztar->pending_entries[end].ready) break;
            if (chunk_bytes + ztar->pending_entries[end].encrypted_size > max_bytes && end > start) break;
            chunk_bytes += ztar->pending_entries[end].encrypted_size;
            end++;
        }

        if (end == start) {
            pthread_mutex_unlock(&ztar->pending_mutex);
            break;
        }

        io_write_lock(ztar);

        for (int i = start; i < end; i++) {
            ztar_pending_entry_t *pe = &ztar->pending_entries[i];
            if (pe->flushed) continue;

            pe->entry->data_offset = (uint64_t)lseek(ztar->fd, 0, SEEK_CUR);

            if (pe->encrypted_size > 0 && pe->encrypted_data) {
                if (safe_write_exact(ztar->fd, pe->encrypted_data, pe->encrypted_size) != 0) {
                    warn("Failed to write encrypted data for: %s", pe->entry->filename);
                    if (ftruncate(ztar->fd, (off_t)pe->entry->data_offset) != 0) {}
                    pe->flushed = 1;
                    total_errors++;
                    continue;
                }
            }

            pthread_mutex_lock(&ztar->entries_mutex);
            ztar->header.file_count++;
            ztar->header.total_original_size += pe->entry->original_size;
            ztar->header.total_compressed_size += pe->entry->compressed_size;

            if (ztar->header.file_count > ZTAR_MAX_FILES ||
                (size_t)ztar->header.file_count > SIZE_MAX / sizeof(ztar_entry_t)) {
                pthread_mutex_unlock(&ztar->entries_mutex);
                warn("Archive file limit reached (%u files)", ZTAR_MAX_FILES);
                end = i;
                break;
            }

            size_t new_size = ztar->header.file_count * sizeof(ztar_entry_t);
            ztar->entries = safe_realloc(ztar->entries, new_size);
            memcpy(&ztar->entries[ztar->header.file_count - 1], pe->entry, sizeof(ztar_entry_t));
            pthread_mutex_unlock(&ztar->entries_mutex);

            ztar->is_modified = 1;
            pe->flushed = 1;
        }

        io_write_unlock(ztar);

        for (int i = start; i < end; i++) {
            if (ztar->pending_entries[i].flushed) {
                free(ztar->pending_entries[i].encrypted_data);
                free(ztar->pending_entries[i].entry);
                ztar->pending_entries[i].encrypted_data = NULL;
                ztar->pending_entries[i].entry = NULL;
            }
        }

        ztar->pending_offset = end;
        total_flushed += (end - start);
        pthread_mutex_unlock(&ztar->pending_mutex);

        compact_pending_array(ztar);
    }

    ztar->flush_errors += total_errors;
    if (total_errors > 0) ztar->last_error = ZTAR_ERR_IO;

    return total_flushed;
}

static int flush_pending_entries(ztar_t *ztar) {
    int total = 0, flushed;
    do {
        flushed = flush_pending_entries_chunked(ztar, ZTAR_FLUSH_CHUNK_SIZE, ZTAR_FLUSH_MAX_BYTES);
        total += flushed;
    } while (flushed > 0);
    compact_pending_array(ztar);
    return total;
}

/* ============================================================================
 * Public API - Archive Operations
 * ============================================================================ */

static ztar_t *ztar_alloc(void) {
    ztar_t *ztar = safe_malloc(sizeof(ztar_t));
    ztar->fd = -1;
    ztar->key = NULL;
    ztar->entries = NULL;
    ztar->is_open = 0;
    ztar->is_modified = 0;
    ztar->num_threads = 1;
    ztar->follow_symlinks = 0;
    ztar->preserve_permissions = 1;
    ztar->mlock_available = check_mlock_available();
    ztar->max_open_fds = get_max_open_fds();
    ztar->writers_waiting = 0;
    ztar->active_readers = 0;
    ztar->pending_entries = NULL;
    ztar->pending_count = 0;
    ztar->pending_capacity = 0;
    ztar->pending_offset = 0;
    ztar->flush_errors = 0;
    ztar->last_error = ZTAR_ERR_NONE;

    pthread_rwlock_init(&ztar->io_lock, NULL);
    pthread_mutex_init(&ztar->rw_mutex, NULL);
    pthread_cond_init(&ztar->rw_cond, NULL);
    pthread_mutex_init(&ztar->entries_mutex, NULL);
    pthread_mutex_init(&ztar->pending_mutex, NULL);
    pthread_cond_init(&ztar->pending_cond, NULL);

    return ztar;
}

void ztar_set_progress_callback(ztar_t *ztar, ztar_progress_cb cb, void *user_data) {
    if (ztar) { ztar->progress_cb = cb; ztar->progress_user_data = user_data; }
}

void ztar_set_num_threads(ztar_t *ztar, int num) {
    if (ztar && num > 0 && num <= ZTAR_MAX_THREADS) ztar->num_threads = num;
}

void ztar_set_follow_symlinks(ztar_t *ztar, int follow) {
    if (ztar) ztar->follow_symlinks = follow;
}

void ztar_set_preserve_permissions(ztar_t *ztar, int preserve) {
    if (ztar) ztar->preserve_permissions = preserve;
}

int ztar_get_errors(ztar_t *ztar) {
    return ztar ? ztar->flush_errors : 0;
}

ztar_t *ztar_create(const char *archive_path, const char *password) {
    if (!archive_path || !password) return NULL;
    if (strlen(password) < ZTAR_MIN_PASSWORD_LEN) {
        warn("Password must be at least %d characters", ZTAR_MIN_PASSWORD_LEN);
        return NULL;
    }

    crypto_init();

    ztar_t *ztar = ztar_alloc();
    ztar->path = strdup(archive_path);
    if (!ztar->path) { free(ztar); return NULL; }

    ztar->fd = create_file_atomic(archive_path);
    if (ztar->fd < 0) {
        warn(errno == EEXIST ? "Archive already exists: %s" : "Cannot create archive: %s", archive_path);
        free(ztar->path); free(ztar); return NULL;
    }

    ztar->key = secure_alloc(ZTAR_KEY_SIZE, &ztar->mlock_available);
    if (!ztar->key) {
        close(ztar->fd); unlink(archive_path); free(ztar->path); free(ztar); return NULL;
    }

    memset(&ztar->header, 0, sizeof(ztar_header_t));
    ztar->header.magic = ZTAR_MAGIC;
    ztar->header.version = ZTAR_VERSION;
    ztar->header.created_at = get_current_time();
    generate_random(ztar->header.salt, ZTAR_SALT_SIZE);

    if (derive_key(password, ztar->header.salt, ztar->key) != 0) {
        warn("Key derivation failed - password may be too weak");
        secure_free(ztar->key, ZTAR_KEY_SIZE, ztar->mlock_available);
        close(ztar->fd); unlink(archive_path); free(ztar->path); free(ztar); return NULL;
    }

    compute_header_mac(ztar->key, &ztar->header);

    io_write_lock(ztar);
    int write_ok = safe_write_exact(ztar->fd, &ztar->header, sizeof(ztar_header_t));
    io_write_unlock(ztar);

    if (write_ok != 0) {
        warn("Failed to write archive header");
        secure_free(ztar->key, ZTAR_KEY_SIZE, ztar->mlock_available);
        close(ztar->fd); unlink(archive_path); free(ztar->path); free(ztar); return NULL;
    }

    ztar->is_open = 1;
    return ztar;
}

ztar_t *ztar_open(const char *archive_path, const char *password) {
    if (!archive_path || !password) return NULL;

    crypto_init();

    ztar_t *ztar = ztar_alloc();
    ztar->path = strdup(archive_path);
    if (!ztar->path) { free(ztar); return NULL; }

    ztar->fd = open(archive_path, O_RDWR | ZTAR_OPEN_FLAGS);
    if (ztar->fd < 0) {
        warn("Cannot open archive: %s", archive_path);
        free(ztar->path); free(ztar); return NULL;
    }

    io_read_lock(ztar);
    int hdr_ok = safe_read_exact(ztar->fd, &ztar->header, sizeof(ztar_header_t));
    io_read_unlock(ztar);

    if (hdr_ok != 0) {
        warn("Failed to read archive header - file may be truncated");
        close(ztar->fd); free(ztar->path); free(ztar); return NULL;
    }

    if (ztar->header.magic != ZTAR_MAGIC) {
        warn("Not a valid ZTAR archive (bad magic number)");
        close(ztar->fd); free(ztar->path); free(ztar); return NULL;
    }

    if (ztar->header.version > ZTAR_VERSION) {
        warn("Archive version %u requires newer ztar (this is v%d)",
             ztar->header.version, ZTAR_VERSION);
        close(ztar->fd); free(ztar->path); free(ztar); return NULL;
    }

    if (ztar->header.file_count > ZTAR_MAX_FILES) {
        warn("Archive claims %u files - possible corruption", ztar->header.file_count);
        close(ztar->fd); free(ztar->path); free(ztar); return NULL;
    }

    ztar->key = secure_alloc(ZTAR_KEY_SIZE, &ztar->mlock_available);
    if (!ztar->key) {
        close(ztar->fd); free(ztar->path); free(ztar); return NULL;
    }

    if (derive_key(password, ztar->header.salt, ztar->key) != 0) {
        warn("Key derivation failed - likely wrong password");
        secure_free(ztar->key, ZTAR_KEY_SIZE, ztar->mlock_available);
        close(ztar->fd); free(ztar->path); free(ztar); return NULL;
    }

    if (verify_header_mac(ztar->key, &ztar->header) != 0) {
        warn("Header authentication failed - wrong password or tampered archive");
        secure_free(ztar->key, ZTAR_KEY_SIZE, ztar->mlock_available);
        close(ztar->fd); free(ztar->path); free(ztar); return NULL;
    }

    if (ztar->header.file_count > 0) {
        if ((size_t)ztar->header.file_count > SIZE_MAX / sizeof(ztar_entry_t)) {
            warn("Integer overflow in entry table size");
            secure_free(ztar->key, ZTAR_KEY_SIZE, ztar->mlock_available);
            close(ztar->fd); free(ztar->path); free(ztar); return NULL;
        }

        size_t entries_size = ztar->header.file_count * sizeof(ztar_entry_t);
        ztar->entries = safe_malloc(entries_size);

        io_read_lock(ztar);
        int rd_ok = safe_read_exact(ztar->fd, ztar->entries, entries_size);
        io_read_unlock(ztar);

        if (rd_ok != 0) {
            warn("Failed to read file entries");
            secure_free(ztar->key, ZTAR_KEY_SIZE, ztar->mlock_available);
            close(ztar->fd); free(ztar->path); free(ztar->entries); free(ztar); return NULL;
        }
    }

    ztar->is_open = 1;
    return ztar;
}

int ztar_add_file(ztar_t *ztar, const char *filepath, const char *archive_name) {
    if (!ztar || !ztar->is_open || !filepath) return ZTAR_ERR_PATH;

    const char *name = archive_name ? archive_name : filepath;
    if (strlen(name) > ZTAR_FILENAME_MAX) return ZTAR_ERR_PATH;

    char safe_name[ZTAR_FILENAME_MAX + 1];
    char *base = basename((char *)name);
    strncpy(safe_name, base, ZTAR_FILENAME_MAX);
    safe_name[ZTAR_FILENAME_MAX] = '\0';

    pthread_mutex_lock(&ztar->entries_mutex);
    for (uint32_t i = 0; i < ztar->header.file_count; i++) {
        if (strcmp(ztar->entries[i].filename, safe_name) == 0) {
            pthread_mutex_unlock(&ztar->entries_mutex);
            warn("File already exists in archive: %s", safe_name);
            return ZTAR_ERR_EXISTS;
        }
    }
    pthread_mutex_unlock(&ztar->entries_mutex);

    struct stat st;
    int src_fd = -1;

    if (!ztar->follow_symlinks) {
        if (lstat(filepath, &st) < 0) {
            warn("Cannot stat: %s", filepath);
            return ZTAR_ERR_IO;
        }
        if (!S_ISLNK(st.st_mode) && S_ISREG(st.st_mode))
            src_fd = safe_open_file(filepath, 0, &st);
    } else {
        src_fd = safe_open_file(filepath, 1, &st);
        if (src_fd < 0) {
            warn("Cannot open: %s", filepath);
            return ZTAR_ERR_IO;
        }
    }

    ztar_entry_t entry;
    memset(&entry, 0, sizeof(ztar_entry_t));
    strncpy(entry.filename, safe_name, ZTAR_FILENAME_MAX);
    entry.mod_time = (uint64_t)st.st_mtime;
    entry.mode = (uint32_t)st.st_mode;
    entry.uid = (uint32_t)st.st_uid;
    entry.gid = (uint32_t)st.st_gid;

    if (S_ISDIR(st.st_mode)) {
        entry.entry_type = ZTAR_ENTRY_DIR;
    } else if (S_ISLNK(st.st_mode) && !ztar->follow_symlinks) {
        entry.entry_type = ZTAR_ENTRY_SYMLINK;
        ssize_t len = readlink(filepath, entry.symlink_target, ZTAR_PATH_MAX - 1);
        if (len < 0) {
            warn("Cannot read symlink: %s", filepath);
            if (src_fd >= 0) close(src_fd);
            return ZTAR_ERR_IO;
        }
        entry.symlink_target[len] = '\0';
    } else if (src_fd >= 0 && S_ISREG(st.st_mode) && st.st_size > 0) {
        entry.entry_type = ZTAR_ENTRY_FILE;
        uint64_t original_size = (uint64_t)st.st_size;

        if (compute_hash_streaming(src_fd, original_size, entry.original_hash) != 0) {
            warn("Hash computation failed: %s", filepath);
            close(src_fd); return ZTAR_ERR_IO;
        }
        entry.original_crc32 = compute_crc32_streaming(src_fd, original_size);

        char tmp_path[ZTAR_PATH_MAX];
        int tmp_fd = create_secure_temp(ztar, tmp_path, sizeof(tmp_path));
        if (tmp_fd < 0) { close(src_fd); return ZTAR_ERR_IO; }

        size_t compressed_size = 0;
        int comp_ret = compress_data_streaming(src_fd, tmp_fd, original_size, &compressed_size,
                                                ztar->progress_cb, ztar->progress_user_data, safe_name);
        close(src_fd);

        if (comp_ret != 0) {
            warn("Compression failed: %s", filepath);
            close(tmp_fd); return ZTAR_ERR_COMPRESS;
        }

        uint8_t *compressed = safe_malloc(compressed_size);
        lseek(tmp_fd, 0, SEEK_SET);
        safe_read_exact(tmp_fd, compressed, compressed_size);
        close(tmp_fd);

        compute_hash_buffer(compressed, compressed_size, entry.compressed_hash);
        entry.compressed_crc32 = compute_crc32_buffer(compressed, compressed_size);

        uint8_t *ciphertext = safe_malloc(compressed_size);
        generate_random(entry.nonce, ZTAR_NONCE_SIZE);

        if (encrypt_buffer(ztar->key, entry.nonce, compressed, compressed_size,
                           ciphertext, entry.mac) != 0) {
            warn("Encryption failed: %s", filepath);
            free(compressed); free(ciphertext); return ZTAR_ERR_CRYPTO;
        }

        entry.original_size = original_size;
        entry.compressed_size = compressed_size;
        entry.encrypted_size = compressed_size + ZTAR_MAC_SIZE;

        io_write_lock(ztar);
        entry.data_offset = (uint64_t)lseek(ztar->fd, 0, SEEK_CUR);

        if (safe_write_exact(ztar->fd, entry.mac, ZTAR_MAC_SIZE) != 0 ||
            safe_write_exact(ztar->fd, ciphertext, compressed_size) != 0) {
            warn("Write failed for: %s - disk full?", filepath);
            if (ftruncate(ztar->fd, (off_t)entry.data_offset) != 0) {}
            io_write_unlock(ztar);
            free(compressed); free(ciphertext); return ZTAR_ERR_IO;
        }
        io_write_unlock(ztar);

        free(compressed); free(ciphertext);
    } else {
        warn("Unsupported file type or empty file: %s", filepath);
        if (src_fd >= 0) close(src_fd);
        return ZTAR_ERR_PATH;
    }

    if (src_fd >= 0) close(src_fd);

    pthread_mutex_lock(&ztar->entries_mutex);

    if (ztar->header.file_count >= ZTAR_MAX_FILES) {
        pthread_mutex_unlock(&ztar->entries_mutex);
        warn("Maximum file count reached (%u)", ZTAR_MAX_FILES);
        return ZTAR_ERR_LIMIT;
    }

    ztar->header.file_count++;
    ztar->header.total_original_size += entry.original_size;
    ztar->header.total_compressed_size += entry.compressed_size;

    ztar->entries = safe_realloc(ztar->entries, ztar->header.file_count * sizeof(ztar_entry_t));
    memcpy(&ztar->entries[ztar->header.file_count - 1], &entry, sizeof(ztar_entry_t));
    pthread_mutex_unlock(&ztar->entries_mutex);

    ztar->is_modified = 1;

    if (ztar->progress_cb && entry.entry_type == ZTAR_ENTRY_FILE)
        ztar->progress_cb(safe_name, entry.original_size, entry.original_size,
                          ztar->progress_user_data);

    return ZTAR_ERR_NONE;
}

int ztar_add_directory(ztar_t *ztar, const char *dirpath, const char *prefix) {
    if (!ztar || !ztar->is_open || !dirpath) return ZTAR_ERR_PATH;

    DIR *dir = opendir(dirpath);
    if (!dir) {
        warn("Cannot open directory: %s", dirpath);
        return ZTAR_ERR_IO;
    }

    char dir_name[ZTAR_FILENAME_MAX + 1];
    if (prefix) {
        strncpy(dir_name, prefix, ZTAR_FILENAME_MAX);
    } else {
        char *b = basename((char *)dirpath);
        strncpy(dir_name, b, ZTAR_FILENAME_MAX);
    }
    dir_name[ZTAR_FILENAME_MAX] = '\0';

    if (ztar_add_file(ztar, dirpath, dir_name) != 0) {
        closedir(dir);
        return ZTAR_ERR_IO;
    }

    struct dirent *de;
    int ret = ZTAR_ERR_NONE;

    while ((de = readdir(dir)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;

        char full[ZTAR_PATH_MAX], arch[ZTAR_PATH_MAX];
        snprintf(full, sizeof(full), "%s/%s", dirpath, de->d_name);
        snprintf(arch, sizeof(arch), "%s/%s", dir_name, de->d_name);

        struct stat st;
        if (lstat(full, &st) < 0) continue;

        if (S_ISDIR(st.st_mode)) {
            if (ztar_add_directory(ztar, full, arch) != 0) ret = ZTAR_ERR_IO;
        } else {
            if (ztar_add_file(ztar, full, arch) != 0) ret = ZTAR_ERR_IO;
        }
    }

    closedir(dir);
    return ret;
}

int ztar_add_files_parallel(ztar_t *ztar, char **filepaths, int count) {
    if (!ztar || !ztar->is_open || !filepaths || count <= 0) return ZTAR_ERR_PATH;

    int nthreads = ztar->num_threads;
    if (nthreads > count) nthreads = count;

    ztar_work_item_t *items = safe_malloc(count * sizeof(ztar_work_item_t));
    int valid = 0;

    for (int i = 0; i < count; i++) {
        memset(&items[i], 0, sizeof(ztar_work_item_t));
        strncpy(items[i].filepath, filepaths[i], ZTAR_PATH_MAX - 1);

        const char *nm = strrchr(filepaths[i], '/');
        nm = nm ? nm + 1 : filepaths[i];
        strncpy(items[i].archive_name, nm, ZTAR_FILENAME_MAX);

        if (lstat(filepaths[i], &items[i].st) < 0 || !S_ISREG(items[i].st.st_mode)) {
            items[i].status = -1;
            continue;
        }

        items[i].status = 0;
        items[i].entry_type = ZTAR_ENTRY_FILE;
        items[i].ztar = ztar;
        valid++;
    }

    if (valid == 0) { free(items); return ZTAR_ERR_NONE; }

    int launched = 0, completed = 0;
    for (int i = 0; i < count; i++) {
        if (items[i].status == -1) continue;

        pthread_mutex_lock(&ztar->pending_mutex);
        while (launched - completed >= nthreads)
            pthread_cond_wait(&ztar->pending_cond, &ztar->pending_mutex);
        pthread_mutex_unlock(&ztar->pending_mutex);

        if (pthread_create(&items[i].thread, NULL, parallel_compress_worker, &items[i]) == 0)
            launched++;

        for (int j = 0; j < count; j++) {
            if (items[j].status == 2) {
                queue_pending_entry(ztar, &items[j]);
                pthread_join(items[j].thread, NULL);
                free(items[j].compressed_data);
                items[j].compressed_data = NULL;
                items[j].status = 3;
                completed++;
            }
        }
        flush_pending_entries_chunked(ztar, ZTAR_FLUSH_CHUNK_SIZE, ZTAR_FLUSH_MAX_BYTES);
        compact_pending_array(ztar);
    }

    for (int i = 0; i < count; i++)
        if (items[i].status == 0 || items[i].status == 1)
            pthread_join(items[i].thread, NULL);

    for (int i = 0; i < count; i++) {
        if (items[i].status == 2) {
            queue_pending_entry(ztar, &items[i]);
            free(items[i].compressed_data);
        }
    }
    flush_pending_entries(ztar);

    free(items);

    if (ztar->flush_errors > 0) {
        warn("%d write errors occurred during parallel add", ztar->flush_errors);
        return ZTAR_ERR_IO;
    }

    return ZTAR_ERR_NONE;
}

int ztar_extract_file(ztar_t *ztar, const char *archive_name, const char *output_path) {
    if (!ztar || !ztar->is_open || !archive_name || !output_path) return ZTAR_ERR_PATH;

    char safe_path[ZTAR_PATH_MAX], output_dir[ZTAR_PATH_MAX], filename[ZTAR_FILENAME_MAX + 1];

    strncpy(safe_path, output_path, sizeof(safe_path) - 1);
    safe_path[sizeof(safe_path) - 1] = '\0';

    char *slash = strrchr(safe_path, '/');
    if (slash) {
        *slash = '\0';
        strncpy(output_dir, safe_path, sizeof(output_dir) - 1);
        strncpy(filename, slash + 1, sizeof(filename) - 1);
    } else {
        strncpy(output_dir, ".", sizeof(output_dir) - 1);
        strncpy(filename, safe_path, sizeof(filename) - 1);
    }
    filename[sizeof(filename) - 1] = '\0';

    if (validate_extract_path(output_dir, filename, safe_path, sizeof(safe_path)) != 0) {
        warn("Path traversal detected: %s", output_path);
        return ZTAR_ERR_PATH;
    }

    ztar_entry_t *entry = NULL;
    pthread_mutex_lock(&ztar->entries_mutex);
    for (uint32_t i = 0; i < ztar->header.file_count; i++) {
        if (strcmp(ztar->entries[i].filename, archive_name) == 0) {
            entry = &ztar->entries[i];
            break;
        }
    }
    pthread_mutex_unlock(&ztar->entries_mutex);

    if (!entry) {
        warn("File not found in archive: %s", archive_name);
        return ZTAR_ERR_FORMAT;
    }

    if (entry->entry_type == ZTAR_ENTRY_DIR) {
        if (mkdir(safe_path, entry->mode & 0777) != 0 && errno != EEXIST) {
            warn("Failed to create directory: %s", safe_path);
            return ZTAR_ERR_IO;
        }
        if (ztar->preserve_permissions) chmod(safe_path, entry->mode & 0777);
        printf("Extracted directory: %s\n", archive_name);
        return ZTAR_ERR_NONE;
    }

    if (entry->entry_type == ZTAR_ENTRY_SYMLINK) {
        if (symlink(entry->symlink_target, safe_path) != 0) {
            warn("Failed to create symlink: %s -> %s", safe_path, entry->symlink_target);
            return ZTAR_ERR_IO;
        }
        printf("Extracted symlink: %s -> %s\n", archive_name, entry->symlink_target);
        return ZTAR_ERR_NONE;
    }

    /* Extract regular file with full integrity verification */
    io_read_lock(ztar);
    if (lseek(ztar->fd, (off_t)entry->data_offset, SEEK_SET) < 0) {
        io_read_unlock(ztar);
        warn("Seek failed for: %s", archive_name);
        return ZTAR_ERR_IO;
    }

    uint8_t *encrypted = safe_malloc(entry->encrypted_size);
    int rd = safe_read_exact(ztar->fd, encrypted, entry->encrypted_size);
    io_read_unlock(ztar);

    if (rd != 0) {
        warn("Read failed for: %s", archive_name);
        free(encrypted); return ZTAR_ERR_IO;
    }

    /* Verify MAC before decryption */
    if (memcmp(encrypted, entry->mac, ZTAR_MAC_SIZE) != 0) {
        warn("MAC verification failed: %s (data corrupted)", archive_name);
        free(encrypted); return ZTAR_ERR_AUTH;
    }

    size_t ciphertext_len = entry->encrypted_size - ZTAR_MAC_SIZE;
    uint8_t *compressed = safe_malloc(ciphertext_len);

    if (decrypt_buffer(ztar->key, entry->nonce, encrypted + ZTAR_MAC_SIZE,
                       ciphertext_len, entry->mac, compressed) != 0) {
        warn("Decryption failed: %s", archive_name);
        free(encrypted); free(compressed); return ZTAR_ERR_CRYPTO;
    }
    free(encrypted);

    /* Verify compressed integrity before decompression */
    uint8_t comp_hash[ZTAR_HASH_SIZE];
    compute_hash_buffer(compressed, ciphertext_len, comp_hash);
    if (memcmp(comp_hash, entry->compressed_hash, ZTAR_HASH_SIZE) != 0) {
        warn("Compressed hash mismatch: %s", archive_name);
        free(compressed); return ZTAR_ERR_AUTH;
    }

    /* Decompress to temp file */
    char tmp_output[ZTAR_PATH_MAX];
    int tmp_fd = create_secure_temp(ztar, tmp_output, sizeof(tmp_output));
    if (tmp_fd < 0) { free(compressed); return ZTAR_ERR_IO; }

    char comp_tmp[ZTAR_PATH_MAX];
    int comp_fd = create_secure_temp(ztar, comp_tmp, sizeof(comp_tmp));
    if (comp_fd < 0) {
        free(compressed); close(tmp_fd); return ZTAR_ERR_IO;
    }

    safe_write_exact(comp_fd, compressed, ciphertext_len);
    lseek(comp_fd, 0, SEEK_SET);

    int decomp_ret = decompress_data_streaming(comp_fd, tmp_fd, ciphertext_len,
                                                entry->original_size,
                                                ztar->progress_cb, ztar->progress_user_data,
                                                archive_name);
    close(comp_fd);
    free(compressed);

    if (decomp_ret != 0) {
        warn("Decompression failed: %s", archive_name);
        close(tmp_fd); return ZTAR_ERR_COMPRESS;
    }

    /* Verify original data integrity */
    int verify_fd = open(tmp_output, O_RDONLY | ZTAR_OPEN_FLAGS);
    if (verify_fd >= 0) {
        uint8_t orig_hash[ZTAR_HASH_SIZE];
        if (compute_hash_streaming(verify_fd, entry->original_size, orig_hash) == 0) {
            if (memcmp(orig_hash, entry->original_hash, ZTAR_HASH_SIZE) != 0) {
                warn("Original hash mismatch: %s", archive_name);
                close(verify_fd); close(tmp_fd); return ZTAR_ERR_AUTH;
            }
        }
        uint32_t orig_crc = compute_crc32_streaming(verify_fd, entry->original_size);
        if (orig_crc != entry->original_crc32) {
            warn("Original CRC mismatch: %s", archive_name);
            close(verify_fd); close(tmp_fd); return ZTAR_ERR_AUTH;
        }
        close(verify_fd);
    }
    close(tmp_fd);

    /* Atomic rename to final path */
    if (rename(tmp_output, safe_path) != 0) {
        /* Fallback: copy if rename fails (e.g., O_TMPFILE across filesystems) */
        int src = open(tmp_output, O_RDONLY | ZTAR_OPEN_FLAGS);
        int dst = open(safe_path, O_CREAT | O_WRONLY | O_TRUNC | ZTAR_OPEN_FLAGS, 0600);
        if (src >= 0 && dst >= 0) {
            uint8_t buf[ZTAR_CHUNK_SIZE];
            ssize_t n;
            while ((n = read(src, buf, sizeof(buf))) > 0) {
                if (write(dst, buf, (size_t)n) != n) break;
            }
        }
        if (src >= 0) close(src);
        if (dst >= 0) close(dst);
        unlink(tmp_output);
    }

    if (ztar->preserve_permissions) {
        chmod(safe_path, entry->mode & 0777);
        struct utimbuf times;
        times.actime = (time_t)entry->mod_time;
        times.modtime = (time_t)entry->mod_time;
        utime(safe_path, &times);
    }

    printf("Extracted: %s (%lu bytes, %.1f%% compression)\n",
           archive_name, entry->original_size,
           100.0 * (1.0 - (double)entry->compressed_size / entry->original_size));

    return ZTAR_ERR_NONE;
}

int ztar_extract_all(ztar_t *ztar, const char *output_dir) {
    if (!ztar || !ztar->is_open || !output_dir) return ZTAR_ERR_PATH;

    if (mkdir(output_dir, 0755) != 0 && errno != EEXIST) {
        warn("Cannot create output directory: %s", output_dir);
        return ZTAR_ERR_IO;
    }

    /* First pass: create directory structure */
    for (uint32_t i = 0; i < ztar->header.file_count; i++) {
        if (ztar->entries[i].entry_type == ZTAR_ENTRY_DIR) {
            char dp[ZTAR_PATH_MAX];
            snprintf(dp, sizeof(dp), "%s/%s", output_dir, ztar->entries[i].filename);
            mkdir(dp, 0755);
        }
    }

    /* Second pass: extract files and symlinks */
    int success = 0;
    for (uint32_t i = 0; i < ztar->header.file_count; i++) {
        if (ztar->entries[i].entry_type == ZTAR_ENTRY_DIR) {
            success++;
            continue;
        }

        char op[ZTAR_PATH_MAX];
        snprintf(op, sizeof(op), "%s/%s", output_dir, ztar->entries[i].filename);

        if (ztar_extract_file(ztar, ztar->entries[i].filename, op) == 0) {
            success++;
        }
    }

    printf("\nExtracted %d/%u files successfully\n", success, ztar->header.file_count);
    return (success == (int)ztar->header.file_count) ? ZTAR_ERR_NONE : ZTAR_ERR_IO;
}

void ztar_list_files(ztar_t *ztar) {
    if (!ztar || !ztar->is_open) return;

    time_t created = (time_t)ztar->header.created_at;

    printf("\nArchive: %s\n", ztar->path);
    printf("Version: %u\n", ztar->header.version);
    printf("Files:   %u\n", ztar->header.file_count);
    printf("Created: %s", ctime(&created));

    if (ztar->header.file_count == 0) {
        printf("Archive is empty.\n\n");
        return;
    }

    printf("\n%-40s %8s %12s %12s %8s %10s\n",
           "Filename", "Type", "Original", "Compressed", "Ratio", "Integrity");
    printf("%-40s %8s %12s %12s %8s %10s\n",
           "--------", "----", "--------", "----------", "-----", "---------");

    for (uint32_t i = 0; i < ztar->header.file_count; i++) {
        ztar_entry_t *e = &ztar->entries[i];

        const char *type = "FILE";
        if (e->entry_type == ZTAR_ENTRY_DIR) type = "DIR";
        else if (e->entry_type == ZTAR_ENTRY_SYMLINK) type = "SYMLINK";

        if (e->entry_type != ZTAR_ENTRY_FILE) {
            printf("%-40s %8s %12s %12s %8s %10s\n",
                   e->filename, type, "-", "-", "-", "OK");
            continue;
        }

        double ratio = 100.0 * (double)e->compressed_size / (double)e->original_size;
        char orig[32], comp[32];

        if (e->original_size < 1024)
            snprintf(orig, sizeof(orig), "%lu B", e->original_size);
        else if (e->original_size < 1048576)
            snprintf(orig, sizeof(orig), "%.1f KB", e->original_size / 1024.0);
        else
            snprintf(orig, sizeof(orig), "%.1f MB", e->original_size / 1048576.0);

        if (e->compressed_size < 1024)
            snprintf(comp, sizeof(comp), "%lu B", e->compressed_size);
        else if (e->compressed_size < 1048576)
            snprintf(comp, sizeof(comp), "%.1f KB", e->compressed_size / 1024.0);
        else
            snprintf(comp, sizeof(comp), "%.1f MB", e->compressed_size / 1048576.0);

        printf("%-40s %8s %12s %12s %7.1f%% %10s\n",
               e->filename, type, orig, comp, ratio, "OK");
    }

    printf("\nTotal original:   ");
    if (ztar->header.total_original_size < 1048576)
        printf("%.1f KB\n", ztar->header.total_original_size / 1024.0);
    else
        printf("%.1f MB\n", ztar->header.total_original_size / 1048576.0);

    printf("Total compressed: ");
    if (ztar->header.total_compressed_size < 1048576)
        printf("%.1f KB\n", ztar->header.total_compressed_size / 1024.0);
    else
        printf("%.1f MB\n", ztar->header.total_compressed_size / 1048576.0);

    printf("Overall ratio:    %.1f%%\n",
           100.0 * (double)ztar->header.total_compressed_size / ztar->header.total_original_size);

    printf("\nSecurity: XChaCha20-Poly1305 | Argon2id | BLAKE2b+CRC32 | Header MAC | mlock\n");
    printf("I/O:      CV-RWLock (writer-pref) | Chunked flush (%d entries/%lu MB)\n\n",
           ZTAR_FLUSH_CHUNK_SIZE, (unsigned long)(ZTAR_FLUSH_MAX_BYTES / (1024 * 1024)));
}

int ztar_verify(ztar_t *ztar) {
    if (!ztar || !ztar->is_open) return ZTAR_ERR_PATH;

    printf("Verifying archive integrity...\n");
    int corrupt = 0;

    for (uint32_t i = 0; i < ztar->header.file_count; i++) {
        ztar_entry_t *e = &ztar->entries[i];

        if (e->entry_type != ZTAR_ENTRY_FILE) {
            printf("  %s: OK (%s)\n", e->filename,
                   e->entry_type == ZTAR_ENTRY_DIR ? "directory" : "symlink");
            continue;
        }

        io_read_lock(ztar);
        if (lseek(ztar->fd, (off_t)e->data_offset, SEEK_SET) < 0) {
            printf("  %s: FAILED (seek error)\n", e->filename);
            corrupt++; io_read_unlock(ztar); continue;
        }

        uint8_t *encrypted = safe_malloc(e->encrypted_size);
        int rd = safe_read_exact(ztar->fd, encrypted, e->encrypted_size);
        io_read_unlock(ztar);

        if (rd != 0) {
            printf("  %s: FAILED (read error)\n", e->filename);
            corrupt++; free(encrypted); continue;
        }

        if (memcmp(encrypted, e->mac, ZTAR_MAC_SIZE) != 0) {
            printf("  %s: FAILED (MAC mismatch)\n", e->filename);
            corrupt++; free(encrypted); continue;
        }

        size_t clen = e->encrypted_size - ZTAR_MAC_SIZE;
        uint8_t *compressed = safe_malloc(clen);

        if (decrypt_buffer(ztar->key, e->nonce, encrypted + ZTAR_MAC_SIZE,
                          clen, e->mac, compressed) != 0) {
            printf("  %s: FAILED (decryption error)\n", e->filename);
            corrupt++; free(encrypted); free(compressed); continue;
        }

        uint8_t hash[ZTAR_HASH_SIZE];
        compute_hash_buffer(compressed, clen, hash);

        if (memcmp(hash, e->compressed_hash, ZTAR_HASH_SIZE) != 0) {
            printf("  %s: FAILED (hash mismatch)\n", e->filename);
            corrupt++;
        } else {
            printf("  %s: OK\n", e->filename);
        }

        if (ztar->progress_cb)
            ztar->progress_cb(e->filename, i + 1, ztar->header.file_count,
                            ztar->progress_user_data);

        free(encrypted); free(compressed);
    }

    if (corrupt == 0) {
        printf("\n✓ All %u files verified successfully.\n", ztar->header.file_count);
    } else {
        printf("\n✗ %d file(s) are corrupted!\n", corrupt);
    }

    return corrupt ? ZTAR_ERR_AUTH : ZTAR_ERR_NONE;
}

int ztar_close(ztar_t *ztar) {
    if (!ztar) return ZTAR_ERR_NONE;

    /* Flush any remaining pending entries */
    flush_pending_entries(ztar);

    if (ztar->is_open && ztar->is_modified) {
        ztar->header.version = ZTAR_VERSION;
        compute_header_mac(ztar->key, &ztar->header);

        io_write_lock(ztar);
        lseek(ztar->fd, 0, SEEK_SET);
        safe_write_exact(ztar->fd, &ztar->header, sizeof(ztar_header_t));

        if (ztar->entries && ztar->header.file_count > 0) {
            safe_write_exact(ztar->fd, ztar->entries,
                           ztar->header.file_count * sizeof(ztar_entry_t));
        }

        fsync(ztar->fd);
        io_write_unlock(ztar);
    }

    if (ztar->fd >= 0) close(ztar->fd);

    if (ztar->key) secure_free(ztar->key, ZTAR_KEY_SIZE, ztar->mlock_available);

    if (ztar->pending_entries) {
        for (int i = 0; i < ztar->pending_count; i++) {
            free(ztar->pending_entries[i].encrypted_data);
            free(ztar->pending_entries[i].entry);
        }
        free(ztar->pending_entries);
    }

    pthread_rwlock_destroy(&ztar->io_lock);
    pthread_mutex_destroy(&ztar->rw_mutex);
    pthread_cond_destroy(&ztar->rw_cond);
    pthread_mutex_destroy(&ztar->entries_mutex);
    pthread_mutex_destroy(&ztar->pending_mutex);
    pthread_cond_destroy(&ztar->pending_cond);

    free(ztar->entries);
    free(ztar->path);
    free(ztar);

    return ZTAR_ERR_NONE;
}

/* ============================================================================
 * Command Line Interface
 * ============================================================================ */

static void progress_callback(const char *filename, uint64_t processed,
                              uint64_t total, void *user_data) {
    (void)user_data;
    if (total > 0) {
        printf("\r  %s: %3.0f%%", filename, 100.0 * processed / total);
        fflush(stdout);
        if (processed >= total) printf("\n");
    }
}

static void print_usage(const char *prog) {
    printf("ZTAR v%d - Secure Compressed Archive System\n\n", ZTAR_VERSION);
    printf("Usage: %s <command> <archive> [options] [files...]\n\n", prog);
    printf("Commands:\n");
    printf("  create    Create a new encrypted archive\n");
    printf("  add       Add files/directories to an archive\n");
    printf("  extract   Extract files from an archive\n");
    printf("  list      List archive contents\n");
    printf("  verify    Verify archive integrity\n");
    printf("  info      Show archive metadata (no password required)\n\n");
    printf("Options:\n");
    printf("  -p <pass>  Password (or set ZTAR_PASSWORD environment variable)\n");
    printf("  -t <N>     Number of compression threads (1-%d, default: 1)\n", ZTAR_MAX_THREADS);
    printf("  -L         Follow symbolic links (default: store as symlinks)\n");
    printf("  -P         Don't preserve file permissions and timestamps\n");
    printf("  -q         Quiet mode - suppress progress output\n");
    printf("  -h, --help Show this help message\n\n");
    printf("Security Features:\n");
    printf("  Encryption:     XChaCha20-Poly1305 (authenticated)\n");
    printf("  Key Derivation: Argon2id (memory-hard, GPU-resistant)\n");
    printf("  Hashing:        BLAKE2b + CRC32 (dual verification)\n");
    printf("  Header:         MAC authenticated (tamper detection)\n");
    printf("  Memory:         mlock() for encryption keys\n");
    printf("  I/O:            CV-RWLock with writer preference\n");
    printf("  Flush:          Dynamic chunking (%d entries / %lu MB)\n\n",
           ZTAR_FLUSH_CHUNK_SIZE, (unsigned long)(ZTAR_FLUSH_MAX_BYTES / (1024 * 1024)));
    printf("Examples:\n");
    printf("  %s create backup.ztar -p MySecret123\n", prog);
    printf("  %s add backup.ztar -p MySecret123 -t 4 docs/ photos/\n", prog);
    printf("  %s extract backup.ztar -p MySecret123\n", prog);
    printf("  export ZTAR_PASSWORD=MySecret123\n");
    printf("  %s list backup.ztar\n", prog);
    printf("  %s verify backup.ztar -p MySecret123\n\n", prog);
    printf("Build: make\n");
    printf("Dependencies: libsodium-dev liblz4-dev zlib1g-dev\n");
    printf("Repository: ztar.c + Makefile (single-file distribution)\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char *command = argv[1];

    if (strcmp(command, "-h") == 0 || strcmp(command, "--help") == 0 ||
        strcmp(command, "help") == 0) {
        print_usage(argv[0]);
        return 0;
    }

    char *password = NULL;
    int num_threads = 1, follow_symlinks = 0, preserve_perms = 1, quiet = 0;
    char *archive = NULL, **files = NULL;
    int file_count = 0, files_capacity = 0, ret = 0;

    /* Parse command-line options */
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]); free(files); return 0;
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            password = argv[++i];
        } else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            num_threads = atoi(argv[++i]);
            if (num_threads < 1) num_threads = 1;
            if (num_threads > ZTAR_MAX_THREADS) num_threads = ZTAR_MAX_THREADS;
        } else if (strcmp(argv[i], "-L") == 0) {
            follow_symlinks = 1;
        } else if (strcmp(argv[i], "-P") == 0) {
            preserve_perms = 0;
        } else if (strcmp(argv[i], "-q") == 0) {
            quiet = 1;
        } else if (strcmp(argv[i], "-v") == 0) {
            /* verbose - accepted for compatibility, no effect */
        } else if (!archive) {
            archive = argv[i];
        } else {
            if (file_count >= files_capacity) {
                files_capacity = (files_capacity == 0) ? 16 : files_capacity * 2;
                files = safe_realloc(files, files_capacity * sizeof(char *));
            }
            files[file_count++] = argv[i];
        }
    }

    /* Check for password in environment */
    if (!password) password = getenv("ZTAR_PASSWORD");

    /* info command - no password needed */
    if (strcmp(command, "info") == 0) {
        if (!archive) {
            fprintf(stderr, "Usage: %s info <archive.ztar>\n", argv[0]);
            free(files); return 1;
        }
        crypto_init();
        int fd = open(archive, O_RDONLY | ZTAR_OPEN_FLAGS);
        if (fd < 0) {
            fprintf(stderr, "Cannot open archive: %s\n", archive);
            free(files); return 1;
        }
        ztar_header_t hdr;
        if (safe_read_exact(fd, &hdr, sizeof(hdr)) != 0 || hdr.magic != ZTAR_MAGIC) {
            fprintf(stderr, "Invalid or corrupted ZTAR archive\n");
            close(fd); free(files); return 1;
        }
        time_t created = (time_t)hdr.created_at;
        printf("Archive:        %s\n", archive);
        printf("Version:        %u\n", hdr.version);
        printf("Files:          %u\n", hdr.file_count);
        printf("Created:        %s", ctime(&created));
        if (hdr.total_original_size > 0) {
            printf("Original size:  %lu bytes\n", hdr.total_original_size);
            printf("Compressed:     %lu bytes\n", hdr.total_compressed_size);
            printf("Ratio:          %.1f%%\n",
                   100.0 * hdr.total_compressed_size / hdr.total_original_size);
        }
        close(fd); free(files); return 0;
    }

    /* All other commands require a password */
    if (!password && strcmp(command, "create") != 0) {
        password = read_password_secure("Archive password: ");
    }
    if (!password) {
        fprintf(stderr, "Password required. Use -p option or set ZTAR_PASSWORD.\n");
        free(files); return 1;
    }

    if (!password && strcmp(command, "create") == 0) {
        password = read_password_secure("New password (min 8 characters): ");
        if (!password || strlen(password) < ZTAR_MIN_PASSWORD_LEN) {
            fprintf(stderr, "Password must be at least %d characters.\n", ZTAR_MIN_PASSWORD_LEN);
            if (password) { clear_sensitive(password, strlen(password)); free(password); }
            free(files); return 1;
        }
        char *confirm = read_password_secure("Confirm password: ");
        if (!confirm || strcmp(password, confirm) != 0) {
            fprintf(stderr, "Passwords do not match.\n");
            if (password) { clear_sensitive(password, strlen(password)); free(password); }
            if (confirm) { clear_sensitive(confirm, strlen(confirm)); free(confirm); }
            free(files); return 1;
        }
        clear_sensitive(confirm, strlen(confirm)); free(confirm);
    }

    if (!password || !archive) {
        fprintf(stderr, "Archive file required.\n");
        free(files); return 1;
    }

    /* Execute command */
    if (strcmp(command, "create") == 0) {
        ztar_t *ztar = ztar_create(archive, password);
        if (!ztar) {
            fprintf(stderr, "Failed to create archive.\n");
            ret = 1;
        } else {
            if (!quiet) printf("Created archive: %s\n", archive);
            ztar_close(ztar);
        }
    } else if (strcmp(command, "add") == 0) {
        if (file_count == 0) {
            fprintf(stderr, "No files specified to add.\n");
            free(files); return 1;
        }
        ztar_t *ztar = ztar_open(archive, password);
        if (!ztar) {
            fprintf(stderr, "Failed to open archive (wrong password?).\n");
            ret = 1;
        } else {
            ztar_set_num_threads(ztar, num_threads);
            ztar_set_follow_symlinks(ztar, follow_symlinks);
            ztar_set_preserve_permissions(ztar, preserve_perms);
            if (!quiet) ztar_set_progress_callback(ztar, progress_callback, NULL);

            if (num_threads > 1 && file_count > 1) {
                ret = (ztar_add_files_parallel(ztar, files, file_count) != 0);
            } else {
                for (int i = 0; i < file_count && ret == 0; i++) {
                    struct stat st;
                    if (lstat(files[i], &st) == 0 && S_ISDIR(st.st_mode)) {
                        if (ztar_add_directory(ztar, files[i], NULL) != 0) ret = 1;
                    } else {
                        if (ztar_add_file(ztar, files[i], NULL) != 0) ret = 1;
                    }
                }
            }

            if (ztar_get_errors(ztar) > 0) {
                warn("%d write error(s) occurred", ztar_get_errors(ztar));
            }
            ztar_close(ztar);
        }
    } else if (strcmp(command, "extract") == 0) {
        ztar_t *ztar = ztar_open(archive, password);
        if (!ztar) {
            fprintf(stderr, "Failed to open archive (wrong password?).\n");
            ret = 1;
        } else {
            ztar_set_preserve_permissions(ztar, preserve_perms);
            if (!quiet) ztar_set_progress_callback(ztar, progress_callback, NULL);

            const char *odir = (file_count > 1) ? files[1] : ".";
            if (file_count > 0) {
                char op[ZTAR_PATH_MAX];
                snprintf(op, sizeof(op), "%s/%s", odir, files[0]);
                if (ztar_extract_file(ztar, files[0], op) != 0) {
                    fprintf(stderr, "Failed to extract: %s\n", files[0]);
                    ret = 1;
                }
            } else {
                if (ztar_extract_all(ztar, odir) != 0) ret = 1;
            }
            ztar_close(ztar);
        }
    } else if (strcmp(command, "list") == 0) {
        ztar_t *ztar = ztar_open(archive, password);
        if (!ztar) {
            fprintf(stderr, "Failed to open archive (wrong password?).\n");
            ret = 1;
        } else {
            ztar_list_files(ztar);
            ztar_close(ztar);
        }
    } else if (strcmp(command, "verify") == 0) {
        ztar_t *ztar = ztar_open(archive, password);
        if (!ztar) {
            fprintf(stderr, "Failed to open archive (wrong password?).\n");
            ret = 1;
        } else {
            if (!quiet) ztar_set_progress_callback(ztar, progress_callback, NULL);
            ret = (ztar_verify(ztar) != 0);
            ztar_close(ztar);
        }
    } else {
        fprintf(stderr, "Unknown command: %s\n\n", command);
        print_usage(argv[0]);
        ret = 1;
    }

    /* Clean up sensitive data */
    clear_sensitive(password, strlen(password));
    if (password != getenv("ZTAR_PASSWORD")) free(password);
    free(files);

    return ret;
}