/*
  usb_fuzzer_fw.c
  - USB fuzzer (fw-mode, SHSH, test-upload-index, exv-diff, SHA1) with integrated ASCII UI
  - UI is always on by default (no opt-out)
  - Embedded version, build date/time, and author info
  - Build: see Makefile (it sets VERSION and AUTHOR at compile-time)
  - WARNING: destructive. Use only on authorized test hardware.
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <inttypes.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <time.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <libusb-1.0/libusb.h>
#include <fcntl.h>
#include <signal.h>
#include <limits.h>
#include <sys/wait.h>
#include <ctype.h>
#include <math.h>

/* Build-time metadata (can be overridden by Makefile -D flags) */
#ifndef VERSION
#define VERSION "1.0.0"
#endif
#ifndef AUTHOR
#define AUTHOR "@planetminguez"
#endif
#define BUILD_DATE (__DATE__ " " __TIME__)

/* ---- Configurable defaults ---- */
#define DEFAULT_TIMEOUT_MS 500
#define DEFAULT_THREADS 1
#define DEFAULT_MAX_INPUT (64*1024)
#define DEFAULT_SHSH_REPEATS 3
#define DEFAULT_SHSH_LEVEL 3
#define TIMING_THRESHOLD_RATIO 0.20

/* Transfer types and transports */
typedef enum { XF_CONTROL, XF_BULK, XF_INTERRUPT } xfer_type_t;
typedef enum { TRANS_CONTROL, TRANS_BULK } transport_t;

/* Image descriptor used by fw-mode */
typedef struct {
    uint32_t magic;
    uint8_t ver_major;
    uint8_t ver_minor;
    uint8_t flags;
    uint8_t reserved;
    uint32_t image_len;
    uint32_t sig_len;
    uint32_t device_id;
    uint8_t iv[16];
} img_desc_t;

/* ---- Options structure ---- */
typedef struct {
    /* common */
    uint16_t vid;
    uint16_t pid;
    int interface;
    unsigned char out_ep;
    unsigned char in_ep;
    xfer_type_t xfer_type;
    int timeout_ms;
    int threads;
    int iterations;
    size_t max_input_size;
    char *corpus_dir;
    char *crash_dir;
    int dry_run;

    /* fw-mode */
    int fw_mode;
    char *fw_image;
    size_t fw_chunk_size;
    int fw_chunk_delay_ms;
    int fw_finalize_via_control;
    uint8_t fw_finalize_req;
    uint16_t fw_finalize_value;
    uint16_t fw_finalize_index;
    int fw_signature_fuzz;
    int fw_encryption_fuzz;
    int fw_device_check;
    int fw_safe_mode;

    /* upload index */
    uint32_t upload_index_start;
    uint32_t upload_index_step;
    uint32_t upload_index_wrap;
    int upload_index_mode; /* 0=none,1=wvalue,2=windex,3=corpus */

    /* descriptor fuzzing */
    int scan_descriptors;
    int fuzz_descriptors;

    /* SHSH-mode */
    int shsh_mode;
    char *shsh_path;
    transport_t shsh_transport;
    uint8_t shsh_ctrl_req;
    uint16_t shsh_ctrl_val;
    uint16_t shsh_ctrl_idx;
    uint8_t shsh_ctrl_bm;
    unsigned char shsh_bulk_ep;
    int shsh_fuzz_level;
    int shsh_timing;
    int shsh_repeats;

    /* test-upload-index feature */
    int test_upload_index;
    int test_index_count;
    size_t exv_offset;
    size_t exv_size;
    int test_upload_safe;

    /* verify probe for test-upload-index and exv-diff */
    int verify_ctrl_req_present;
    uint8_t verify_ctrl_req;
    uint16_t verify_ctrl_val;
    uint16_t verify_ctrl_idx;
    uint8_t verify_ctrl_bm;
    char *verify_expected;

    /* exv-diff and sha1 tests */
    int exv_diff_test;
    int sha1_test;
    uint8_t sha1_read_req;
    uint16_t sha1_read_val;
    uint16_t sha1_read_idx;
    uint8_t sha1_read_bm;
    int sha1_read_len;

    /* UI (always enabled) */
    int ui_enabled;
} options_t;

static options_t g_opt;

/* ---- Global runtime state ---- */
static volatile int stop_flag = 0;
static pthread_mutex_t save_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t index_lock = PTHREAD_MUTEX_INITIALIZER;
static uint32_t upload_index = 0;

/* corpus */
typedef struct { uint8_t *data; size_t size; } buffer_t;
static buffer_t *g_corpus = NULL;
static size_t g_corpus_count = 0;
static size_t g_corpus_capacity = 0;
static pthread_mutex_t corpus_lock = PTHREAD_MUTEX_INITIALIZER;

/* logging */
static int logfile_fd = -1;
static char log_path[PATH_MAX] = {0};

/* ---- Utility helpers ---- */
static void die(const char *fmt, ...) __attribute__((noreturn));
static void die(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap);
    exit(1);
}
static uint64_t rng_state = 0;
static uint64_t xorshift64star(void) {
    if (rng_state == 0) rng_state = (uint64_t)time(NULL) ^ (uint64_t)getpid();
    uint64_t x = rng_state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    rng_state = x * 2685821657736338717ULL;
    return rng_state;
}
static void msleep(long ms) { struct timespec ts = { ms/1000, (ms%1000)*1000000L }; nanosleep(&ts, NULL); }

/* file read helper */
static uint8_t *read_file_alloc(const char *path, size_t *out_size) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return NULL;
    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return NULL; }
    size_t sz = (size_t)st.st_size;
    if (sz > g_opt.max_input_size) sz = g_opt.max_input_size;
    uint8_t *buf = malloc(sz);
    if (!buf) { close(fd); return NULL; }
    ssize_t r = read(fd, buf, sz);
    if (r < 0) { free(buf); close(fd); return NULL; }
    *out_size = (size_t)r;
    close(fd);
    return buf;
}

/* corpus management */
static void add_to_corpus(const uint8_t *data, size_t size) {
    pthread_mutex_lock(&corpus_lock);
    if (g_corpus_count >= g_corpus_capacity) {
        size_t newcap = (g_corpus_capacity == 0) ? 64 : g_corpus_capacity * 2;
        buffer_t *nb = realloc(g_corpus, newcap * sizeof(buffer_t));
        if (!nb) { fprintf(stderr, "OOM\n"); exit(1); }
        g_corpus = nb; g_corpus_capacity = newcap;
    }
    uint8_t *copy = malloc(size);
    memcpy(copy, data, size);
    g_corpus[g_corpus_count].data = copy;
    g_corpus[g_corpus_count].size = size;
    g_corpus_count++;
    pthread_mutex_unlock(&corpus_lock);
}
static void load_corpus_dir(const char *dir) {
    if (!dir) return;
    DIR *d = opendir(dir);
    if (!d) { fprintf(stderr, "Failed to open corpus dir '%s'\n", dir); return; }
    struct dirent *ent;
    char path[PATH_MAX];
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);
        struct stat st;
        if (stat(path, &st) != 0) continue;
        if (!S_ISREG(st.st_mode)) continue;
        size_t sz = 0; uint8_t *data = read_file_alloc(path, &sz);
        if (data && sz > 0) add_to_corpus(data, sz);
        free(data);
        if (g_corpus_count >= 10000) break;
    }
    closedir(d);
    fprintf(stderr, "Loaded %zu corpus files\n", g_corpus_count);
}

/* Small helpers for header */
static void store_u32_be(uint8_t *p, uint32_t v) { p[0] = (v>>24)&0xFF; p[1] = (v>>16)&0xFF; p[2] = (v>>8)&0xFF; p[3] = (v)&0xFF; }
static uint32_t be32(const uint8_t *p) { return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|((uint32_t)p[3]); }
static size_t compose_header(uint8_t *buf, size_t buflen, const img_desc_t *d) {
    if (buflen < 36) return 0;
    store_u32_be(buf+0, d->magic);
    buf[4] = d->ver_major; buf[5] = d->ver_minor; buf[6] = d->flags; buf[7] = d->reserved;
    store_u32_be(buf+8, d->image_len); store_u32_be(buf+12, d->sig_len); store_u32_be(buf+16, d->device_id);
    memcpy(buf+20, d->iv, 16);
    return 36;
}

/* ---- SHSH heuristics and mutators (condensed) ---- */
static int find_sig_blob(const uint8_t *buf, size_t buf_sz, size_t *out_off, size_t *out_len) {
    for (size_t i = 0; i + 4 < buf_sz; ++i) {
        if (buf[i] == 0x30) {
            size_t idx = i + 1;
            if (idx >= buf_sz) continue;
            uint8_t lb = buf[idx++];
            size_t len = 0;
            if ((lb & 0x80) == 0) len = lb;
            else {
                int n = lb & 0x7F;
                if (n == 0 || n > 4) continue;
                if (idx + n > buf_sz) continue;
                for (int x = 0; x < n; ++x) { len = (len << 8) | buf[idx++]; }
            }
            size_t seq_end = idx + len;
            if (seq_end > buf_sz) continue;
            for (size_t j = i + 2; j + 2 < seq_end; ++j) {
                if (buf[j] == 0x03 || buf[j] == 0x04) {
                    size_t k = j + 1; if (k >= seq_end) continue;
                    uint8_t lbb = buf[k++]; size_t slen = 0;
                    if ((lbb & 0x80) == 0) slen = lbb;
                    else {
                        int nn = lbb & 0x7F; if (nn == 0 || nn > 4) continue;
                        if (k + nn > seq_end) continue;
                        for (int x=0;x<nn;x++) slen = (slen<<8) | buf[k++];
                    }
                    if (k + slen <= seq_end) { *out_off = k; *out_len = slen; return 0; }
                }
            }
        }
    }
    return -1;
}
static void mutate_flip_bytes(uint8_t *buf, size_t sz, int flips) {
    if (!buf || sz==0) return;
    for (int i=0;i<flips;i++) { size_t pos = xorshift64star()%sz; buf[pos] ^= (uint8_t)(xorshift64star() & 0xFF); }
}
static void mutate_asn1_len_corrupt(uint8_t *buf, size_t sz) {
    for (size_t i=0;i+1<sz;i++){ uint8_t b=buf[i]; if (b==0x30||b==0x03||b==0x04){ size_t idx=i+1; if (idx<sz) { buf[idx]=(uint8_t)(xorshift64star() & 0xFF); return; } } }
}

/* generate SHSH mutants (aggressive by default) */
static uint8_t **shsh_generate_mutations(const uint8_t *orig, size_t orig_sz, size_t *out_count, int level, size_t max_payload) {
    int target = (level==1) ? 8 : (level==2) ? 24 : 64;
    uint8_t **ret = calloc(target, sizeof(uint8_t*));
    int count = 0;
    for (int i=0;i<target;i++) {
        size_t sz = orig_sz;
        uint8_t *c = malloc(sz);
        memcpy(c, orig, sz);
        uint64_t r = xorshift64star() % 100;
        if (r < 20) { /* truncate */
            size_t cut = 1 + (xorshift64star() % sz); size_t newsz = sz - cut; if (newsz < 1) newsz = 1; sz = newsz;
        } else if (r < 50) { int flips = 1 + (xorshift64star() % (level*4)); mutate_flip_bytes(c, sz, flips); }
        else if (r < 70) mutate_asn1_len_corrupt(c, sz);
        else if (r < 85) {
            size_t off=0, sl=0;
            if (find_sig_blob(c, sz, &off, &sl)==0 && sl>0) {
                int flips = 1 + (xorshift64star()% (int)(sl>0?sl:1));
                for (int f=0; f<flips; ++f) { size_t pos = off + (xorshift64star()%sl); c[pos] ^= (uint8_t)(xorshift64star() & 0xFF); }
            } else mutate_flip_bytes(c, sz, 4);
        } else {
            for (int b=0;b<(int)(level*8);b++) { size_t pos = xorshift64star()%sz; c[pos] = (uint8_t)(xorshift64star() & 0xFF); }
        }
        ret[count++] = c;
    }
    *out_count = count;
    return ret;
}

/* ---- Upload helpers (fw-mode) ---- */
static void save_fw_crash(const uint8_t *header, size_t header_sz, const uint8_t *sent_chunks[], const size_t chunk_sz[], int chunk_count, const uint8_t *sig, size_t sig_len, const char *reason, uint32_t index_used) {
    pthread_mutex_lock(&save_lock);
    struct timeval tv; gettimeofday(&tv, NULL);
    char base[PATH_MAX]; snprintf(base, sizeof(base), "%s/fw_crash_%ld_%06ld_idx%u", g_opt.crash_dir, tv.tv_sec, (int)tv.tv_usec, index_used);
    char binpath[PATH_MAX]; snprintf(binpath, sizeof(binpath), "%s.bin", base);
    int fd = open(binpath, O_CREAT|O_WRONLY, 0644);
    if (fd >= 0) {
        if (header && header_sz>0) write(fd, header, header_sz);
        uint32_t cc = (uint32_t)chunk_count; write(fd, &cc, sizeof(cc));
        for (int i=0;i<chunk_count;i++){
            uint32_t s = (uint32_t)chunk_sz[i]; write(fd, &s, sizeof(s));
            if (chunk_sz[i]>0) write(fd, sent_chunks[i], chunk_sz[i]);
        }
        uint32_t sl = (uint32_t)sig_len; write(fd, &sl, sizeof(sl));
        if (sig_len>0) write(fd, sig, sig_len);
        close(fd);
    }
    char meta[PATH_MAX]; snprintf(meta, sizeof(meta), "%s.txt", base);
    FILE *mf = fopen(meta, "w");
    if (mf) { fprintf(mf, "reason=%s\nindex=%" PRIu32 "\nchunks=%d\nsig_len=%zu\n", reason, index_used, chunk_count, sig_len); fclose(mf); }
    fprintf(stderr, "Saved FW crash: %s (%s) index=%" PRIu32 "\n", binpath, reason, index_used);
    pthread_mutex_unlock(&save_lock);
}

static int upload_image_sequence(libusb_device_handle *handle, const uint8_t *header, size_t header_sz, const uint8_t *image, size_t image_sz, const uint8_t *sig, size_t sig_len, uint32_t idx_for_meta) {
    const int cs = (g_opt.fw_chunk_size == 0) ? 1024 : (int)g_opt.fw_chunk_size;
    const int max_chunks = 4096;
    const uint8_t *sent_chunks[4096];
    size_t chunk_sz[4096];
    int chunk_count = 0;

    if (!g_opt.dry_run) {
        int ret = libusb_control_transfer(handle, LIBUSB_ENDPOINT_OUT | LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_RECIPIENT_DEVICE, 0x02, 0, 0, (uint8_t*)header, (uint16_t)header_sz, g_opt.timeout_ms);
        if (ret < 0) { save_fw_crash(header, header_sz, NULL, NULL, 0, sig, sig_len, "start_control_failed", idx_for_meta); return ret; }
    }

    size_t offset = 0;
    while (offset < image_sz) {
        int this_sz = (int)((image_sz - offset) > (size_t)cs ? cs : (image_sz - offset));
        uint8_t *chunkbuf = malloc(this_sz); memcpy(chunkbuf, image + offset, this_sz);
        int r = 0;
        if (g_opt.dry_run) r = 0;
        else {
            if (g_opt.xfer_type == XF_BULK) {
                int transferred = 0;
                r = libusb_bulk_transfer(handle, g_opt.out_ep, chunkbuf, this_sz, &transferred, g_opt.timeout_ms);
            } else {
                r = libusb_control_transfer(handle, LIBUSB_ENDPOINT_OUT | LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_RECIPIENT_DEVICE, 0x03, 0, 0, chunkbuf, this_sz, g_opt.timeout_ms);
            }
        }
        sent_chunks[chunk_count] = chunkbuf; chunk_sz[chunk_count] = this_sz; chunk_count++;
        if (r != 0) { save_fw_crash(header, header_sz, sent_chunks, chunk_sz, chunk_count, sig, sig_len, "chunk_upload_err", idx_for_meta); for (int i=0;i<chunk_count;i++) free((void*)sent_chunks[i]); return r; }
        offset += this_sz;
        if (g_opt.fw_chunk_delay_ms > 0) msleep(g_opt.fw_chunk_delay_ms);
        if (chunk_count >= max_chunks) break;
    }

    if (sig_len > 0) {
        uint8_t *sigcopy = malloc(sig_len); memcpy(sigcopy, sig, sig_len);
        int r = 0;
        if (g_opt.dry_run) r = 0;
        else {
            if (g_opt.xfer_type == XF_BULK) {
                int transferred = 0;
                r = libusb_bulk_transfer(handle, g_opt.out_ep, sigcopy, (int)sig_len, &transferred, g_opt.timeout_ms);
            } else {
                r = libusb_control_transfer(handle, LIBUSB_ENDPOINT_OUT | LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_RECIPIENT_DEVICE, 0x04, 0, 0, sigcopy, (uint16_t)sig_len, g_opt.timeout_ms);
            }
        }
        if (r != 0) { save_fw_crash(header, header_sz, sent_chunks, chunk_sz, chunk_count, sig, sig_len, "sig_upload_failed", idx_for_meta); for (int i=0;i<chunk_count;i++) free((void*)sent_chunks[i]); free(sigcopy); return r; }
        free(sigcopy);
    }

    if (g_opt.fw_finalize_via_control && !g_opt.dry_run) {
        int ret = libusb_control_transfer(handle, LIBUSB_ENDPOINT_OUT | LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_RECIPIENT_DEVICE, g_opt.fw_finalize_req, g_opt.fw_finalize_value, g_opt.fw_finalize_index, NULL, 0, g_opt.timeout_ms);
        if (ret < 0) { save_fw_crash(header, header_sz, sent_chunks, chunk_sz, chunk_count, sig, sig_len, "finalize_failed", idx_for_meta); for (int i=0;i<chunk_count;i++) free((void*)sent_chunks[i]); return ret; }
    }

    for (int i=0;i<chunk_count;i++) free((void*)sent_chunks[i]);
    return 0;
}

/* ---- Exception-vector differential test and SHA1 read helpers ---- */
static void mutate_exception_vector(uint8_t *image, size_t image_sz, size_t exv_offset, size_t exv_size, int aggressive) {
    if (exv_offset >= image_sz) return;
    size_t max_mut = exv_size;
    if (exv_offset + max_mut > image_sz) max_mut = image_sz - exv_offset;
    if (max_mut == 0) return;
    if (aggressive) {
        for (size_t i = 0; i < max_mut; ++i) if ((xorshift64star()%100) < 80) image[exv_offset + i] = (uint8_t)(xorshift64star() & 0xFF);
    } else {
        int flips = 1 + (xorshift64star()%8);
        for (int f=0; f<flips; ++f) { size_t pos = exv_offset + (xorshift64star()%max_mut); image[pos] ^= (uint8_t)(1u << (xorshift64star()%8)); }
    }
}

/* run verify control (if configured) */
static int run_verify_control(libusb_device_handle *handle, char *response_buf, size_t response_buf_len, int *out_len) {
    if (!g_opt.verify_ctrl_req_present) return -2;
    uint8_t bm = g_opt.verify_ctrl_bm ? g_opt.verify_ctrl_bm : (LIBUSB_ENDPOINT_IN | LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_RECIPIENT_DEVICE);
    int ret = libusb_control_transfer(handle, bm, g_opt.verify_ctrl_req, g_opt.verify_ctrl_val, g_opt.verify_ctrl_idx, (unsigned char*)response_buf, (uint16_t)response_buf_len, g_opt.timeout_ms);
    if (ret < 0) return -1;
    if (out_len) *out_len = ret;
    if (g_opt.verify_expected && g_opt.verify_expected[0]) {
        size_t need = strlen(g_opt.verify_expected);
        if ((size_t)ret < need) return 1;
        if (memcmp(response_buf, g_opt.verify_expected, need) == 0) return 0;
        return 1;
    }
    return 0;
}

/* SHA1 implementation (compact) */
typedef struct { uint32_t h[5]; uint8_t block[64]; uint64_t bitlen; size_t blocklen; } sha1_ctx;
static void sha1_init(sha1_ctx *c) { c->h[0]=0x67452301; c->h[1]=0xEFCDAB89; c->h[2]=0x98BADCFE; c->h[3]=0x10325476; c->h[4]=0xC3D2E1F0; c->bitlen=0; c->blocklen=0; }
static uint32_t rotr(uint32_t x,int s){ return (x<<s)|(x>>(32-s)); }
static void sha1_transform(sha1_ctx *c,const uint8_t *b){
    uint32_t w[80];
    for(int i=0;i<16;i++) w[i]=((uint32_t)b[4*i]<<24)|((uint32_t)b[4*i+1]<<16)|((uint32_t)b[4*i+2]<<8)|((uint32_t)b[4*i+3]);
    for(int i=16;i<80;i++) w[i]=rotr(w[i-3]^w[i-8]^w[i-14]^w[i-16],1);
    uint32_t a=c->h[0],bb=c->h[1],d=c->h[2],e=c->h[3],f=c->h[4];
    for(int i=0;i<80;i++){
        uint32_t k, tmp;
        if (i<20) { tmp = (bb & d) | ((~bb) & e); k = 0x5A827999; }
        else if (i<40) { tmp = bb ^ d ^ e; k = 0x6ED9EBA1; }
        else if (i<60) { tmp = (bb & d) | (bb & e) | (d & e); k = 0x8F1BBCDC; }
        else { tmp = bb ^ d ^ e; k = 0xCA62C1D6; }
        tmp = rotr(a,5) + tmp + f + k + w[i];
        f = e; e = d; d = rotr(bb,30); bb = a; a = tmp;
    }
    c->h[0]+=a; c->h[1]+=bb; c->h[2]+=d; c->h[3]+=e; c->h[4]+=f;
}
static void sha1_update(sha1_ctx *c,const uint8_t *data,size_t len){
    while(len>0){
        size_t tocopy = (len < 64 - c->blocklen) ? len : (64 - c->blocklen);
        memcpy(c->block + c->blocklen, data, tocopy); c->blocklen += tocopy; data += tocopy; len -= tocopy;
        if (c->blocklen == 64) { sha1_transform(c, c->block); c->bitlen += 512; c->blocklen = 0; }
    }
}
static void sha1_final(sha1_ctx *c, uint8_t out[20]){
    uint64_t bitlen = c->bitlen + c->blocklen * 8;
    c->block[c->blocklen++] = 0x80;
    if (c->blocklen > 56) { while(c->blocklen < 64) c->block[c->blocklen++] = 0; sha1_transform(c,c->block); c->blocklen=0; }
    while(c->blocklen < 56) c->block[c->blocklen++] = 0;
    for (int i=7;i>=0;i--) c->block[c->blocklen++] = (bitlen >> (i*8)) & 0xFF;
    sha1_transform(c,c->block);
    for (int i=0;i<5;i++) { out[4*i] = (c->h[i]>>24)&0xFF; out[4*i+1] = (c->h[i]>>16)&0xFF; out[4*i+2] = (c->h[i]>>8)&0xFF; out[4*i+3] = (c->h[i])&0xFF; }
}

/* read device SHA1 registers and compare */
static int perform_sha1_check_for(libusb_device_handle *handle, const uint8_t *image, size_t image_sz) {
    if (!g_opt.sha1_test) return 0;
    int read_len = g_opt.sha1_read_len > 0 ? g_opt.sha1_read_len : 20;
    uint8_t resp[64]; memset(resp,0,sizeof(resp));
    uint8_t bm = g_opt.sha1_read_bm ? g_opt.sha1_read_bm : (LIBUSB_ENDPOINT_IN | LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_RECIPIENT_DEVICE);
    int ret = libusb_control_transfer(handle, bm, g_opt.sha1_read_req, g_opt.sha1_read_val, g_opt.sha1_read_idx, resp, (uint16_t)read_len, g_opt.timeout_ms);
    if (ret < 0) return ret;
    int got = ret;
    uint8_t local[20];
    sha1_ctx ctx; sha1_init(&ctx); sha1_update(&ctx, image, image_sz); sha1_final(&ctx, local);
    if (got < 20) return 1;
    if (memcmp(resp, local, 20) != 0) return 2; /* mismatch */
    return 0; /* OK */
}

/* ---- SHSH send helpers ---- */
static int send_payload_and_time(libusb_device_handle *h, const uint8_t *payload, size_t payload_sz, double *out_ms, transport_t t, uint8_t ctrl_bm, uint8_t ctrl_req, uint16_t ctrl_val, uint16_t ctrl_idx, unsigned char bulk_ep) {
    struct timespec t0,t1; clock_gettime(CLOCK_MONOTONIC,&t0);
    int rc = 0;
    if (t == TRANS_CONTROL) {
        uint8_t bm = ctrl_bm ? ctrl_bm : (LIBUSB_ENDPOINT_OUT | LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_RECIPIENT_DEVICE);
        int ret = libusb_control_transfer(h, bm, ctrl_req, ctrl_val, ctrl_idx, (unsigned char*)payload, (uint16_t)(payload_sz>65535?65535:payload_sz), g_opt.timeout_ms);
        rc = ret < 0 ? ret : 0;
    } else {
        int transferred = 0;
        int ret = libusb_bulk_transfer(h, bulk_ep, (unsigned char*)payload, (int)payload_sz, &transferred, g_opt.timeout_ms);
        rc = ret;
    }
    clock_gettime(CLOCK_MONOTONIC,&t1);
    double ms = (t1.tv_sec - t0.tv_sec)*1e3 + (t1.tv_nsec-t0.tv_nsec)/1e6;
    if (out_ms) *out_ms = ms;
    return rc;
}
static int measure_avg_ms(libusb_device_handle *h, const uint8_t *payload, size_t payload_sz, int repeats, double *out_avg_ms, transport_t t, uint8_t ctrl_bm, uint8_t ctrl_req, uint16_t ctrl_val, uint16_t ctrl_idx, unsigned char bulk_ep, int *out_rc) {
    double total=0.0; int last_rc=0;
    for (int i=0;i<repeats;i++) {
        double ms=0.0; int rc = send_payload_and_time(h, payload, payload_sz, &ms, t, ctrl_bm, ctrl_req, ctrl_val, ctrl_idx, bulk_ep);
        last_rc = rc; if (rc == LIBUSB_ERROR_NO_DEVICE) return -1; total += ms; usleep(1000 + (xorshift64star() % 2000));
    }
    *out_avg_ms = total/repeats; if (out_rc) *out_rc = last_rc; return 0;
}

/* ---- Worker: simplified integration of modes (fw/shsh/test-index/exv-diff/sha1) ---- */
static void *worker_thread(void *arg) {
    (void)arg;
    libusb_context *ctx = NULL;
    libusb_init(&ctx);
    libusb_set_option(ctx, LIBUSB_OPTION_LOG_LEVEL, LIBUSB_LOG_LEVEL_NONE);

    /* preload files */
    uint8_t *shsh_orig = NULL; size_t shsh_orig_sz = 0;
    if (g_opt.shsh_mode && g_opt.shsh_path) shsh_orig = read_file_alloc(g_opt.shsh_path, &shsh_orig_sz);
    uint8_t *fw_img = NULL; size_t fw_img_sz = 0;
    if (g_opt.fw_mode && g_opt.fw_image) fw_img = read_file_alloc(g_opt.fw_image, &fw_img_sz);

    int iterations = g_opt.iterations;
    while (!stop_flag && (iterations == 0 || iterations-- > 0)) {
        libusb_device_handle *handle = libusb_open_device_with_vid_pid(ctx, g_opt.vid, g_opt.pid);
        if (!handle) { fprintf(stderr, "warning: cannot open device %04x:%04x\n", g_opt.vid, g_opt.pid); msleep(500); continue; }
        if (g_opt.interface >= 0) {
            if (libusb_kernel_driver_active(handle, g_opt.interface) == 1) libusb_detach_kernel_driver(handle, g_opt.interface);
            int rc = libusb_claim_interface(handle, g_opt.interface);
            if (rc != 0) { fprintf(stderr, "warn: claim interface %d failed: %s\n", g_opt.interface, libusb_error_name(rc)); libusb_close(handle); msleep(100); continue; }
        }

        /* TEST UPLOAD INDEX (including exv-diff and sha1) */
        if (g_opt.test_upload_index) {
            uint8_t *base_image = NULL; size_t base_image_sz = 0;
            if (fw_img) { base_image_sz = fw_img_sz; base_image = malloc(base_image_sz); memcpy(base_image, fw_img, base_image_sz); }
            else { base_image_sz = 4096; if (base_image_sz > g_opt.max_input_size) base_image_sz = g_opt.max_input_size; base_image = malloc(base_image_sz); for (size_t i=0;i<base_image_sz;i++) base_image[i] = (uint8_t)(xorshift64star() & 0xFF); }
            size_t sig_len = 256; uint8_t *sig = malloc(sig_len); for (size_t i=0;i<sig_len;i++) sig[i] = (uint8_t)(xorshift64star() & 0xFF);

            uint32_t idx = g_opt.upload_index_start;
            int to_run = g_opt.test_index_count > 0 ? g_opt.test_index_count : 1;
            for (int t = 0; t < to_run && !stop_flag; ++t) {
                img_desc_t desc; desc.magic = 0x4657F00Du; desc.ver_major=1; desc.ver_minor=0; desc.flags=0; desc.reserved=0;
                desc.image_len = (uint32_t)base_image_sz; desc.sig_len = (uint32_t)sig_len; desc.device_id = idx;
                for (int i=0;i<16;i++) desc.iv[i] = (uint8_t)(xorshift64star() & 0xFF);
                uint8_t header[64]; size_t header_sz = compose_header(header, sizeof(header), &desc);

                int rc_base = upload_image_sequence(handle, header, header_sz, base_image, base_image_sz, sig, sig_len, idx);
                char resp_base[512]; int resp_base_len=0; int verify_base = run_verify_control(handle, resp_base, sizeof(resp_base), &resp_base_len);

                /* per-byte exv diff test */
                if (g_opt.exv_diff_test) {
                    for (size_t b = 0; b < g_opt.exv_size && !stop_flag; ++b) {
                        uint8_t *mut_img = malloc(base_image_sz); memcpy(mut_img, base_image, base_image_sz);
                        size_t pos = g_opt.exv_offset + b;
                        if (pos < base_image_sz) mut_img[pos] ^= 0xFF;
                        int rc_mut = upload_image_sequence(handle, header, header_sz, mut_img, base_image_sz, sig, sig_len, idx);
                        char resp_mut[512]; int resp_mut_len=0; int verify_mut = run_verify_control(handle, resp_mut, sizeof(resp_mut), &resp_mut_len);

                        int mutated_accepted = 0;
                        if (rc_mut == 0) {
                            if (verify_mut == 0) mutated_accepted = 1;
                            else if (verify_mut == -2) mutated_accepted = 1;
                        }
                        if (mutated_accepted) {
                            pthread_mutex_lock(&save_lock);
                            struct timeval tv; gettimeofday(&tv, NULL);
                            char basefn[PATH_MAX]; snprintf(basefn, sizeof(basefn), "%s/exv_byte_accept_%ld_%06ld_idx%u_b%zu", g_opt.crash_dir, tv.tv_sec, (int)tv.tv_usec, idx, b);
                            char bin[PATH_MAX]; snprintf(bin, sizeof(bin), "%s.bin", basefn);
                            int fd = open(bin, O_CREAT|O_WRONLY, 0644);
                            if (fd>=0) { write(fd, mut_img, base_image_sz); close(fd); }
                            char meta[PATH_MAX]; snprintf(meta, sizeof(meta), "%s.txt", basefn);
                            FILE *mf = fopen(meta, "w");
                            if (mf) { fprintf(mf, "index=%u byte=%zu exv_offset=%zu\nrc_base=%d rc_mut=%d verify_base=%d verify_mut=%d\n", idx, b, g_opt.exv_offset, rc_base, rc_mut, verify_base, verify_mut); fclose(mf); }
                            pthread_mutex_unlock(&save_lock);
                        }
                        free(mut_img);
                    }
                }

                /* SHA1 test */
                if (g_opt.sha1_test) {
                    int sha_rc = perform_sha1_check_for(handle, base_image, base_image_sz);
                    if (sha_rc != 0) {
                        fprintf(stderr, "SHA1 check mismatch or error (rc=%d) for index %u\n", sha_rc, idx);
                        pthread_mutex_lock(&save_lock);
                        struct timeval tv; gettimeofday(&tv, NULL);
                        char basefn[PATH_MAX]; snprintf(basefn, sizeof(basefn), "%s/sha1_mismatch_%ld_%06ld_idx%u", g_opt.crash_dir, tv.tv_sec, (int)tv.tv_usec, idx);
                        char bin[PATH_MAX]; snprintf(bin, sizeof(bin), "%s.bin", basefn);
                        int fd = open(bin, O_CREAT|O_WRONLY, 0644);
                        if (fd>=0) { write(fd, base_image, base_image_sz); close(fd); }
                        char meta[PATH_MAX]; snprintf(meta, sizeof(meta), "%s.txt", basefn);
                        FILE *mf = fopen(meta, "w");
                        if (mf) { fprintf(mf, "sha_rc=%d idx=%u\n", sha_rc, idx); fclose(mf); }
                        pthread_mutex_unlock(&save_lock);
                    } else {
                        fprintf(stderr, "SHA1 check OK for index %u\n", idx);
                    }
                }

                idx += g_opt.upload_index_step;
                if (g_opt.upload_index_wrap > 0) idx %= g_opt.upload_index_wrap;
            }

            free(base_image); free(sig);
        }

        /* SHSH-mode (mutations & timing) */
        if (g_opt.shsh_mode) {
            uint8_t *seed = NULL; size_t seed_sz = 0;
            if (shsh_orig) { seed_sz = shsh_orig_sz; seed = malloc(seed_sz); memcpy(seed, shsh_orig, seed_sz); }
            else {
                seed_sz = 128; seed = malloc(seed_sz);
                memset(seed, 0, seed_sz); seed[0]=0x30; seed[1]=(uint8_t)(seed_sz-2); seed[2]=0x04; seed[3]=(uint8_t)(seed_sz-4);
                for (size_t i=4;i<seed_sz;i++) seed[i] = (uint8_t)(xorshift64star() & 0xFF);
            }
            double baseline_ms = 0.0; int baseline_rc = 0;
            if (g_opt.shsh_timing && shsh_orig) {
                int brc=0;
                if (measure_avg_ms(handle, shsh_orig, shsh_orig_sz, g_opt.shsh_repeats, &baseline_ms, g_opt.shsh_transport, g_opt.shsh_ctrl_bm, g_opt.shsh_ctrl_req, g_opt.shsh_ctrl_val, g_opt.shsh_ctrl_idx, g_opt.shsh_bulk_ep, &brc) == 0) baseline_rc = brc;
            }
            size_t mut_count=0; uint8_t **mutants = shsh_generate_mutations(seed, seed_sz, &mut_count, g_opt.shsh_fuzz_level, g_opt.max_input_size);
            for (size_t m=0;m<mut_count && !stop_flag;m++) {
                uint8_t *mut = mutants[m]; size_t mut_sz = seed_sz; if (mut_sz > g_opt.max_input_size) mut_sz = g_opt.max_input_size;
                double sample_ms=0.0; int sample_rc=0;
                if (g_opt.shsh_timing) {
                    int mc = measure_avg_ms(handle, mut, mut_sz, g_opt.shsh_repeats, &sample_ms, g_opt.shsh_transport, g_opt.shsh_ctrl_bm, g_opt.shsh_ctrl_req, g_opt.shsh_ctrl_val, g_opt.shsh_ctrl_idx, g_opt.shsh_bulk_ep, &sample_rc);
                    if (mc < 0) {
                        pthread_mutex_lock(&save_lock);
                        struct timeval tv; gettimeofday(&tv, NULL);
                        char basefn[PATH_MAX]; snprintf(basefn,sizeof(basefn),"%s/shsh_no_device_%ld_%06ld",g_opt.crash_dir, tv.tv_sec, (int)tv.tv_usec);
                        char bin[PATH_MAX]; snprintf(bin,sizeof(bin),"%s.bin",basefn); int fd=open(bin,O_CREAT|O_WRONLY,0644); if (fd>=0){write(fd,mut,mut_sz);close(fd);}
                        pthread_mutex_unlock(&save_lock);
                        free(mut); continue;
                    }
                } else {
                    double ms=0.0; int rc = send_payload_and_time(handle, mut, mut_sz, &ms, g_opt.shsh_transport, g_opt.shsh_ctrl_bm, g_opt.shsh_ctrl_req, g_opt.shsh_ctrl_val, g_opt.shsh_ctrl_idx, g_opt.shsh_bulk_ep);
                    sample_ms=ms; sample_rc=rc;
                }
                int interesting=0; char reason[128]={0};
                if (sample_rc != 0 && sample_rc != baseline_rc) { interesting=1; snprintf(reason, sizeof(reason), "rc_change:%d_vs_%d", sample_rc, baseline_rc); }
                else if (g_opt.shsh_timing && baseline_ms > 0.0) {
                    double diff = sample_ms - baseline_ms;
                    if (fabs(diff) > baseline_ms * TIMING_THRESHOLD_RATIO) { interesting=1; snprintf(reason,sizeof(reason),"timing_diff:%.3f_vs_%.3f", sample_ms, baseline_ms); }
                }
                if (!interesting && (sample_rc == LIBUSB_ERROR_PIPE || sample_rc == LIBUSB_ERROR_OVERFLOW || sample_rc == LIBUSB_ERROR_IO)) { interesting=1; snprintf(reason,sizeof(reason),"libusb_err:%d", sample_rc); }
                if (interesting) {
                    pthread_mutex_lock(&save_lock);
                    struct timeval tv; gettimeofday(&tv, NULL);
                    char basefn[PATH_MAX]; snprintf(basefn,sizeof(basefn),"%s/shsh_art_%ld_%06ld",g_opt.crash_dir,tv.tv_sec,(int)tv.tv_usec);
                    char bin[PATH_MAX]; snprintf(bin,sizeof(bin),"%s.bin",basefn); int fd=open(bin,O_CREAT|O_WRONLY,0644); if (fd>=0){write(fd,mut,mut_sz);close(fd);}
                    char meta[PATH_MAX]; snprintf(meta,sizeof(meta),"%s.txt",basefn); FILE *mf = fopen(meta,"w"); if (mf){ fprintf(mf,"reason=%s\nsample_ms=%.3f baseline_ms=%.3f\n", reason, sample_ms, baseline_ms); fclose(mf); }
                    pthread_mutex_unlock(&save_lock);
                }
                free(mut);
            }
            free(mutants); if (seed) free(seed);
        }

        if (g_opt.interface >= 0) libusb_release_interface(handle, g_opt.interface);
        libusb_close(handle);
        msleep(100);
    }

    if (shsh_orig) free(shsh_orig);
    if (fw_img) free(fw_img);
    libusb_exit(ctx);
    return NULL;
}

/* ---- Logging & UI support ---- */
static void setup_logging_and_redirect(void) {
    if (!g_opt.crash_dir) return;
    snprintf(log_path, sizeof(log_path), "%s/fuzzer.log", g_opt.crash_dir);
    logfile_fd = open(log_path, O_CREAT | O_WRONLY | O_APPEND, 0644);
    if (logfile_fd < 0) {
        perror("open log");
        return;
    }
    fflush(NULL);
    dup2(logfile_fd, STDOUT_FILENO);
    dup2(logfile_fd, STDERR_FILENO);
}

/* read last N lines from file into dynamically allocated string (caller frees) */
static char *tail_file_lines(const char *path, int lines) {
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long pos = ftell(f);
    int count = 0;
    long cur = pos;
    char *buf = NULL;
    size_t buflen = 0;
    size_t cap = 0;
    while (cur > 0 && count <= lines && buflen < 64*1024) {
        long step = 1024;
        if (cur < step) step = cur;
        cur -= step;
        fseek(f, cur, SEEK_SET);
        char tmp[1025];
        size_t r = fread(tmp, 1, step, f);
        for (long i = (long)r-1; i >= 0; --i) {
            if (tmp[i] == '\n') {
                count++;
                if (count > lines) {
                    long start = cur + i + 1;
                    fseek(f, start, SEEK_SET);
                    size_t remaining = pos - start;
                    if (remaining > 64*1024) remaining = 64*1024;
                    buf = malloc(remaining+1);
                    fread(buf,1,remaining,f);
                    buf[remaining] = 0;
                    fclose(f); return buf;
                }
            }
        }
        cur = ftell(f);
    }
    fseek(f, 0, SEEK_SET);
    size_t toread = pos > 64*1024 ? 64*1024 : pos;
    if (toread == 0) { fclose(f); return strdup(""); }
    if (pos > 64*1024) fseek(f, pos - toread, SEEK_SET);
    buf = malloc(toread + 1);
    fread(buf,1,toread,f);
    buf[toread]=0;
    fclose(f);
    return buf;
}

/* UI thread: prints ASCII banner and status, refreshes periodically */
static void *ui_thread_fn(void *arg) {
    (void)arg;
    time_t start = time(NULL);
    while (!stop_flag) {
        time_t now = time(NULL);
        int uptime = (int)(now - start);
        int hh = uptime/3600, mm=(uptime%3600)/60, ss=uptime%60;

        /* compute crash count and last crash */
        int crash_count = 0;
        char last_crash[PATH_MAX] = "-";
        if (g_opt.crash_dir) {
            DIR *d = opendir(g_opt.crash_dir);
            if (d) {
                struct dirent *ent;
                time_t latest = 0;
                while ((ent = readdir(d)) != NULL) {
                    if (ent->d_name[0] == '.') continue;
                    char path[PATH_MAX]; snprintf(path, sizeof(path), "%s/%s", g_opt.crash_dir, ent->d_name);
                    struct stat st;
                    if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
                        crash_count++;
                        if (st.st_mtime > latest) { latest = st.st_mtime; strncpy(last_crash, ent->d_name, sizeof(last_crash)-1); }
                    }
                }
                closedir(d);
            }
        }

        /* determine modes string */
        char modes[128] = "";
        if (g_opt.fw_mode) strcat(modes, "FW ");
        if (g_opt.shsh_mode) strcat(modes, "SHSH ");
        if (g_opt.test_upload_index) strcat(modes, "TESTIDX ");
        if (g_opt.exv_diff_test) strcat(modes, "EXV-DIFF ");
        if (g_opt.sha1_test) strcat(modes, "SHA1 ");

        /* tail log */
        char *logtail = NULL;
        if (logfile_fd >= 0 && log_path[0]) logtail = tail_file_lines(log_path, 8);

        /* render */
        printf("\033[2J\033[H");
        printf("  ____  _  _  ____   __  __  ____  _   _  _____  ____  \n");
        printf(" |  _ \\| || |/ ___| |  \\/  |/ ___|| | | |/ ____|/ ___| \n");
        printf(" | |_) | || | |  _  | |\\/| | |  _ | | | | (___ | |     \n");
        printf(" |  _ <|__   _| |_| | |  | | |_| || |_| |\\___ \\| |___  \n");
        printf(" |_| \\_\\  |_|  \\____|_|  |_|\\____| \\___/ |____/ \\____| \n");
        printf("       USB Fuzzer FW - Integrated ASCII UI               \n\n");

        printf("+-------------------------------+------------------------+\n");
        printf("| Modes: %-27s | Uptime: %02d:%02d:%02d |\n", modes[0]?modes:"(none)", hh, mm, ss);
        printf("| Crashes: %-24d | Threads: %-10d |\n", crash_count, g_opt.threads);
        printf("| Last crash: %-24s | PID: %-10d |\n", last_crash, getpid());
        printf("+-------------------------------+------------------------+\n\n");

        if (logtail) {
            printf("-- Recent log --\n%s\n", logtail);
            free(logtail);
        } else {
            printf("-- Recent log unavailable --\n");
        }

        printf("\nVersion: %s   Build: %s   Author: %s\n", VERSION, BUILD_DATE, AUTHOR);
        printf("(Press Ctrl-C to stop)\n");
        fflush(stdout);
        for (int i=0;i<4 && !stop_flag;i++) msleep(250);
    }
    return NULL;
}

/* ---- Signal handler ---- */
static void on_sigint(int s) { (void)s; stop_flag = 1; }

/* ---- CLI parsing ---- */
static void print_usage(const char *p) {
    fprintf(stderr,
        "Usage: %s --vid 0xVVVV --pid 0xPPPP --crashes DIR [options]\n"
        "  --version                 print version/build/author and exit\n"
        "Common:\n"
        "  --vid 0xVVVV --pid 0xPPPP\n"
        "  --crashes DIR   Directory to save crashes & logs (required)\n"
        "  --corpus DIR\n"
        "  --jobs N --iterations N --timeout MS --max-input BYTES\n"
        "  --dry-run\n"
        "Modes:\n"
        "  --fw-mode --fw-image PATH --fw-chunk-size BYTES --fw-chunk-delay MS --fw-finalize-ctrl REQ VAL IDX\n"
        "  --shsh-mode --shsh-path FILE --shsh-transport control|bulk --shsh-ctrl-req N --shsh-bulk-ep 0xEE\n"
        "  --test-upload-index --test-index-count N --exv-offset N --exv-size N --exv-diff-test --sha1-test\n"
        "  --verify-ctrl-req N --verify-expected STR\n"
        "  --help\n");
}

/* parse hex helper */
static int parse_hex_u16(const char *s, uint16_t *out) { char *end = NULL; long v = strtol(s, &end, 0); if (end == s) return -1; *out = (uint16_t)v; return 0; }

int main(int argc, char **argv) {
    memset(&g_opt,0,sizeof(g_opt));
    g_opt.timeout_ms = DEFAULT_TIMEOUT_MS;
    g_opt.threads = DEFAULT_THREADS;
    g_opt.iterations = 0;
    g_opt.max_input_size = DEFAULT_MAX_INPUT;
    g_opt.fw_chunk_size = 1024;
    g_opt.upload_index_step = 1;
    g_opt.shsh_fuzz_level = DEFAULT_SHSH_LEVEL;
    g_opt.shsh_repeats = DEFAULT_SHSH_REPEATS;
    g_opt.shsh_transport = TRANS_CONTROL;
    g_opt.exv_offset = 0; g_opt.exv_size = 64;
    g_opt.test_index_count = 1;
    g_opt.sha1_read_len = 20;
    g_opt.ui_enabled = 1; /* fixed: UI always enabled */

    if (argc < 2) { print_usage(argv[0]); return 1; }
    for (int i=1;i<argc;i++) {
        if (strcmp(argv[i],"--version")==0) {
            printf("usb_fuzzer_fw %s\nBuild: %s\nAuthor: %s\n", VERSION, BUILD_DATE, AUTHOR);
            return 0;
        }
        if (strcmp(argv[i],"--vid")==0 && i+1<argc) { if (parse_hex_u16(argv[++i], &g_opt.vid)!=0) die("Invalid vid\n"); }
        else if (strcmp(argv[i],"--pid")==0 && i+1<argc) { if (parse_hex_u16(argv[++i], &g_opt.pid)!=0) die("Invalid pid\n"); }
        else if (strcmp(argv[i],"--crashes")==0 && i+1<argc) g_opt.crash_dir = argv[++i];
        else if (strcmp(argv[i],"--corpus")==0 && i+1<argc) g_opt.corpus_dir = argv[++i];
        else if (strcmp(argv[i],"--jobs")==0 && i+1<argc) g_opt.threads = atoi(argv[++i]);
        else if (strcmp(argv[i],"--iterations")==0 && i+1<argc) g_opt.iterations = atoi(argv[++i]);
        else if (strcmp(argv[i],"--timeout")==0 && i+1<argc) g_opt.timeout_ms = atoi(argv[++i]);
        else if (strcmp(argv[i],"--max-input")==0 && i+1<argc) g_opt.max_input_size = (size_t)atol(argv[++i]);
        else if (strcmp(argv[i],"--dry-run")==0) g_opt.dry_run = 1;

        /* fw */
        else if (strcmp(argv[i],"--fw-mode")==0) g_opt.fw_mode = 1;
        else if (strcmp(argv[i],"--fw-image")==0 && i+1<argc) g_opt.fw_image = argv[++i];
        else if (strcmp(argv[i],"--fw-chunk-size")==0 && i+1<argc) g_opt.fw_chunk_size = (size_t)atol(argv[++i]);
        else if (strcmp(argv[i],"--fw-chunk-delay")==0 && i+1<argc) g_opt.fw_chunk_delay_ms = atoi(argv[++i]);
        else if (strcmp(argv[i],"--fw-finalize-ctrl")==0 && i+3<argc) { g_opt.fw_finalize_via_control = 1; g_opt.fw_finalize_req = (uint8_t)atoi(argv[++i]); g_opt.fw_finalize_value = (uint16_t)atoi(argv[++i]); g_opt.fw_finalize_index = (uint16_t)atoi(argv[++i]); }
        else if (strcmp(argv[i],"--fw-signature-fuzz")==0) g_opt.fw_signature_fuzz = 1;
        else if (strcmp(argv[i],"--fw-encryption-fuzz")==0) g_opt.fw_encryption_fuzz = 1;
        else if (strcmp(argv[i],"--fw-device-check")==0) g_opt.fw_device_check = 1;
        else if (strcmp(argv[i],"--fw-safe-mode")==0) g_opt.fw_safe_mode = 1;

        /* upload index */
        else if (strcmp(argv[i],"--upload-index-start")==0 && i+1<argc) g_opt.upload_index_start = (uint32_t)strtoul(argv[++i],NULL,0);
        else if (strcmp(argv[i],"--upload-index-step")==0 && i+1<argc) g_opt.upload_index_step = (uint32_t)strtoul(argv[++i],NULL,0);
        else if (strcmp(argv[i],"--upload-index-wrap")==0 && i+1<argc) g_opt.upload_index_wrap = (uint32_t)strtoul(argv[++i],NULL,0);
        else if (strcmp(argv[i],"--upload-index-mode")==0 && i+1<argc) { char *m=argv[++i]; if (strcmp(m,"wvalue")==0) g_opt.upload_index_mode=1; else if (strcmp(m,"windex")==0) g_opt.upload_index_mode=2; else if (strcmp(m,"corpus")==0) g_opt.upload_index_mode=3; else g_opt.upload_index_mode=0; }

        /* shsh */
        else if (strcmp(argv[i],"--shsh-mode")==0) g_opt.shsh_mode = 1;
        else if (strcmp(argv[i],"--shsh-path")==0 && i+1<argc) g_opt.shsh_path = argv[++i];
        else if (strcmp(argv[i],"--shsh-transport")==0 && i+1<argc) { char *t = argv[++i]; if (strcmp(t,"control")==0) g_opt.shsh_transport = TRANS_CONTROL; else if (strcmp(t,"bulk")==0) g_opt.shsh_transport = TRANS_BULK; }
        else if (strcmp(argv[i],"--shsh-ctrl-req")==0 && i+1<argc) g_opt.shsh_ctrl_req = (uint8_t)atoi(argv[++i]);
        else if (strcmp(argv[i],"--shsh-ctrl-val")==0 && i+1<argc) g_opt.shsh_ctrl_val = (uint16_t)atoi(argv[++i]);
        else if (strcmp(argv[i],"--shsh-ctrl-idx")==0 && i+1<argc) g_opt.shsh_ctrl_idx = (uint16_t)atoi(argv[++i]);
        else if (strcmp(argv[i],"--shsh-ctrl-bm")==0 && i+1<argc) g_opt.shsh_ctrl_bm = (uint8_t)atoi(argv[++i]);
        else if (strcmp(argv[i],"--shsh-bulk-ep")==0 && i+1<argc) g_opt.shsh_bulk_ep = (unsigned char)strtol(argv[++i], NULL, 0);
        else if (strcmp(argv[i],"--shsh-fuzz-level")==0 && i+1<argc) g_opt.shsh_fuzz_level = atoi(argv[++i]);
        else if (strcmp(argv[i],"--shsh-timing")==0) g_opt.shsh_timing = 1;
        else if (strcmp(argv[i],"--shsh-repeats")==0 && i+1<argc) g_opt.shsh_repeats = atoi(argv[++i]);

        /* test upload index */
        else if (strcmp(argv[i],"--test-upload-index")==0) g_opt.test_upload_index = 1;
        else if (strcmp(argv[i],"--test-index-count")==0 && i+1<argc) g_opt.test_index_count = atoi(argv[++i]);
        else if (strcmp(argv[i],"--exv-offset")==0 && i+1<argc) g_opt.exv_offset = (size_t)atol(argv[++i]);
        else if (strcmp(argv[i],"--exv-size")==0 && i+1<argc) g_opt.exv_size = (size_t)atol(argv[++i]);
        else if (strcmp(argv[i],"--test-upload-safe")==0) g_opt.test_upload_safe = 1;
        else if (strcmp(argv[i],"--exv-diff-test")==0) g_opt.exv_diff_test = 1;

        else if (strcmp(argv[i],"--verify-ctrl-req")==0 && i+1<argc) { g_opt.verify_ctrl_req_present = 1; g_opt.verify_ctrl_req = (uint8_t)atoi(argv[++i]); }
        else if (strcmp(argv[i],"--verify-ctrl-val")==0 && i+1<argc) g_opt.verify_ctrl_val = (uint16_t)atoi(argv[++i]);
        else if (strcmp(argv[i],"--verify-ctrl-idx")==0 && i+1<argc) g_opt.verify_ctrl_idx = (uint16_t)atoi(argv[++i]);
        else if (strcmp(argv[i],"--verify-ctrl-bm")==0 && i+1<argc) g_opt.verify_ctrl_bm = (uint8_t)atoi(argv[++i]);
        else if (strcmp(argv[i],"--verify-expected")==0 && i+1<argc) g_opt.verify_expected = argv[++i];

        /* SHA1 */
        else if (strcmp(argv[i],"--sha1-test")==0) g_opt.sha1_test = 1;
        else if (strcmp(argv[i],"--sha1-read-req")==0 && i+1<argc) g_opt.sha1_read_req = (uint8_t)atoi(argv[++i]);
        else if (strcmp(argv[i],"--sha1-read-val")==0 && i+1<argc) g_opt.sha1_read_val = (uint16_t)atoi(argv[++i]);
        else if (strcmp(argv[i],"--sha1-read-idx")==0 && i+1<argc) g_opt.sha1_read_idx = (uint16_t)atoi(argv[++i]);
        else if (strcmp(argv[i],"--sha1-read-bm")==0 && i+1<argc) g_opt.sha1_read_bm = (uint8_t)atoi(argv[++i]);
        else if (strcmp(argv[i],"--sha1-read-len")==0 && i+1<argc) g_opt.sha1_read_len = atoi(argv[++i]);

        else if (strcmp(argv[i],"--help")==0) { print_usage(argv[0]); return 0; }
        else die("Unknown arg: %s\n", argv[i]);
    }

    if (!g_opt.crash_dir) die("You must supply --crashes DIR\n");
    struct stat st; if (stat(g_opt.crash_dir, &st) != 0) { if (mkdir(g_opt.crash_dir, 0755) != 0) die("Failed to create crash dir\n"); }

    if (g_opt.corpus_dir) load_corpus_dir(g_opt.corpus_dir);
    upload_index = g_opt.upload_index_start;

    if (g_opt.shsh_mode) fprintf(stderr, "WARNING: SHSH fuzzing enabled. Use only on authorized hardware.\n");
    if (g_opt.test_upload_index) fprintf(stderr, "WARNING: test-upload-index enabled. This can brick devices.\n");

    /* setup logging redirection so UI can tail it */
    setup_logging_and_redirect();

    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);

    /* start worker threads */
    int jobs = g_opt.threads > 0 ? g_opt.threads : 1;
    pthread_t *tids = calloc(jobs, sizeof(pthread_t));
    for (int i=0;i<jobs;i++) {
        if (pthread_create(&tids[i], NULL, worker_thread, NULL) != 0) die("failed to create worker\n");
    }

    /* start UI thread (always on) */
    pthread_t ui_thread = 0;
    if (pthread_create(&ui_thread, NULL, ui_thread_fn, NULL) != 0) fprintf(stderr, "warning: failed to start UI thread\n");

    /* wait for workers */
    for (int i=0;i<jobs;i++) pthread_join(tids[i], NULL);
    if (ui_thread) pthread_join(ui_thread, NULL);

    if (logfile_fd >= 0) close(logfile_fd);
    free(tids);
    return 0;
}