/* Standalone engine proof: mount a real NTFS image through ntfs_bridge and
 * exercise every op. Build:
 *   clang -I../../refs/ntfs-3g/include test_bridge.c ntfs_bridge.c \
 *         ../../refs/ntfs-3g/libntfs-3g/.libs/libntfs-3g.a -o /tmp/test_bridge
 * Run:  /tmp/test_bridge <path-to-ntfs-image>
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "ntfs_bridge.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

/* Sums covered bytes. phys == -1 (read-as-zeros: sparse or uninitialized)
 * counts as coverage too — the kernel gets zero-fill extents for those. */
static int count_extents(void *c, long long logical, long long phys, long long len) {
    (void)logical;
    assert(phys == -1 || phys > 0);
    *(long long *)c += len;
    return 0;
}

/* Sums only REAL data bytes — for asserting initialized regions map as data. */
static int count_data_extents(void *c, long long logical, long long phys, long long len) {
    (void)logical;
    if (phys > 0) *(long long *)c += len;
    return 0;
}

static int print_entry(void *ctx, const nk_dirent *e) {
    (void)ctx;
    printf("  %s%s  %lld bytes  (inode %llu)\n", e->name,
           e->is_dir ? "/" : "", e->size, (unsigned long long)e->inode);
    return 0;
}

static int count_names(void *ctx, const char *name) {
    (void)name;
    (*(long long *)ctx)++;
    return 0;
}

/* file-backed nk_io for exercising the callback-device paths (fsck) */
static int g_fd = -1;
static long long file_pread(void *ctx, void *buf, long long count, long long off) {
    (void)ctx;
    return (long long)pread(g_fd, buf, (size_t)count, (off_t)off);
}
static long long file_pwrite(void *ctx, const void *buf, long long count, long long off) {
    (void)ctx;
    return (long long)pwrite(g_fd, buf, (size_t)count, (off_t)off);
}

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: %s <ntfs.img>\n", argv[0]); return 2; }
    char err[256];

    g_fd = open(argv[1], O_RDWR);
    assert(g_fd >= 0);
    struct stat stimg;
    assert(fstat(g_fd, &stimg) == 0);
    nk_io fio = { .ctx = NULL, .pread = file_pread, .pwrite = file_pwrite,
                  .size = (long long)stimg.st_size, .readonly = 0 };

    printf("engine: %s\n", nk_engine_version());
    nk_volume *v = nk_mount(argv[1], 0, err, sizeof(err));
    if (!v) { fprintf(stderr, "mount failed: %s\n", err); return 1; }
    printf("mounted rw\n");

    long long total = 0, freeb = 0; int cs = 0;
    assert(nk_statvfs(v, &total, &freeb, &cs) == 0);
    printf("volume: %lld MB total, %lld MB free, cluster %d\n",
           total >> 20, freeb >> 20, cs);

    /* create dir + file, write, read back */
    nk_delete(v, "/t/hello.txt");            /* clean rerun leftovers */
    nk_delete(v, "/t/renamed.txt");
    nk_delete(v, "/t");
    assert(nk_mkdir(v, "/", "t") == 0);
    assert(nk_create(v, "/t", "hello.txt") == 0);

    const char *msg = "ntfskit: native NTFS write via libntfs-3g!\n";
    long long n = nk_write(v, "/t/hello.txt", 0, (long long)strlen(msg), msg);
    assert(n == (long long)strlen(msg));

    char buf[128] = {0};
    n = nk_read(v, "/t/hello.txt", 0, sizeof(buf), buf);
    assert(n == (long long)strlen(msg));
    assert(strcmp(buf, msg) == 0);
    printf("write+read-back ok: %s", buf);

    /* stat */
    nk_stat st;
    assert(nk_stat_path(v, "/t/hello.txt", &st) == 0);
    assert(!st.is_dir && st.size == (long long)strlen(msg));
    printf("stat ok: size=%lld inode=%llu mtime=%lld\n",
           st.size, (unsigned long long)st.inode, st.mtime);

    /* rename, truncate, list, delete */
    assert(nk_rename(v, "/t/hello.txt", "/t", "renamed.txt") == 0);
    assert(nk_stat_path(v, "/t/renamed.txt", &st) == 0);
    assert(nk_stat_path(v, "/t/hello.txt", &st) != 0);
    assert(nk_truncate(v, "/t/renamed.txt", 10) == 0);
    assert(nk_stat_path(v, "/t/renamed.txt", &st) == 0 && st.size == 10);
    printf("rename+truncate ok\n/ listing:\n");
    assert(nk_list(v, "/", print_entry, NULL) == 0);

    /* set_times */
    assert(nk_set_times(v, "/t/renamed.txt", 1000000000LL, 1111111111LL, -1) == 0);
    assert(nk_stat_path(v, "/t/renamed.txt", &st) == 0);
    assert(st.mtime == 1111111111LL && st.atime == 1000000000LL);
    printf("set_times ok\n");

    /* symlink round-trip */
    nk_delete(v, "/t/link");
    assert(nk_create_symlink(v, "/t", "link", "renamed.txt") == 0);
    char target[256] = {0};
    assert(nk_readlink(v, "/t/link", target, sizeof(target)) == 0);
    printf("symlink ok: -> %s\n", target);
    assert(nk_stat_path(v, "/t/link", &st) == 0 && st.is_symlink);
    assert(nk_delete(v, "/t/link") == 0);

    /* blockmap: write a 64KB file, expect >= 1 data extent covering it */
    assert(nk_create(v, "/t", "big.bin") == 0);
    char blk[4096];
    memset(blk, 0xAB, sizeof(blk));
    for (int i = 0; i < 16; i++)
        assert(nk_write(v, "/t/big.bin", i * 4096LL, 4096, blk) == 4096);
    long long covered = 0;
    int br = nk_blockmap(v, "/t/big.bin", 0, 65536, 0, 512, count_extents, &covered);
    printf("blockmap rc=%d covered=%lld\n", br, covered);
    assert(br == 0 && covered == 65536);

    /* blockmap for write beyond EOF must grow the file (solid clusters) */
    covered = 0;
    assert(nk_blockmap(v, "/t/big.bin", 65536, 65536, 1, 512, count_extents, &covered) == 0);
    assert(covered == 65536);
    assert(nk_stat_path(v, "/t/big.bin", &st) == 0 && st.size == 131072);
    printf("blockmap write-extend ok (size=%lld)\n", st.size);

    /* the extension is allocated but uninitialized: reads must cover it with
     * ZERO extents (no data leak), and after nk_complete_write the same
     * window must map as real data */
    covered = 0;
    assert(nk_blockmap(v, "/t/big.bin", 65536, 65536, 0, 512, count_data_extents, &covered) == 0);
    assert(covered == 0);
    assert(nk_complete_write(v, "/t/big.bin", 65536, 65536) == 0);
    covered = 0;
    assert(nk_blockmap(v, "/t/big.bin", 65536, 65536, 0, 512, count_data_extents, &covered) == 0);
    assert(covered == 65536);
    printf("complete_write ok (uninit->zeros, then data)\n");
    assert(nk_delete(v, "/t/big.bin") == 0);

    /* xattr as ADS: set / get / list / remove roundtrip */
    assert(nk_create(v, "/t", "x.txt") == 0);
    assert(nk_xattr_set(v, "/t/x.txt", "com.apple.metadata:test", "hello", 5) == 0);
    char xbuf[16] = {0};
    assert(nk_xattr_get(v, "/t/x.txt", "com.apple.metadata:test", xbuf, 16) == 5);
    assert(memcmp(xbuf, "hello", 5) == 0);
    assert(nk_xattr_get(v, "/t/x.txt", "com.apple.metadata:test", NULL, 0) == 5);
    assert(nk_xattr_set(v, "/t/x.txt", "com.apple.metadata:test", "hi", 2) == 0);
    assert(nk_xattr_get(v, "/t/x.txt", "com.apple.metadata:test", xbuf, 16) == 2);
    long long xcount = 0;
    assert(nk_xattr_list(v, "/t/x.txt", count_names, &xcount) == 0);
    assert(xcount == 1);
    assert(nk_xattr_remove(v, "/t/x.txt", "com.apple.metadata:test") == 0);
    xcount = 0;
    assert(nk_xattr_list(v, "/t/x.txt", count_names, &xcount) == 0);
    assert(xcount == 0);
    assert(nk_delete(v, "/t/x.txt") == 0);
    printf("xattr roundtrip ok\n");

    /* volume label */
    assert(nk_set_label(v, "RELABELED") == 0);
    char label[64] = {0};
    assert(nk_label(v, label, 64) == 0);
    assert(strcmp(label, "RELABELED") == 0);
    printf("set_label ok\n");

    assert(nk_delete(v, "/t/renamed.txt") == 0);
    assert(nk_delete(v, "/t") == 0);
    assert(nk_sync(v) == 0);
    assert(nk_umount(v) == 0);

    /* fsck over file-backed callback io */
    assert(nk_fsck(&fio, 0, NULL, 0) >= 0);
    assert(nk_fsck(&fio, 1, NULL, 0) >= 0);
    printf("fsck ok\n");

#ifdef TEST_FORMAT
    /* format the image via mkntfs, then mount + write to prove it took —
     * TWICE, because a second in-process run exercises the getopt/static
     * re-entry fixes */
    for (int round = 0; round < 2; round++) {
        const char *lbl = round ? "NKFORMAT2" : "NKFORMAT";
        assert(nk_format(&fio, lbl, err, sizeof(err)) == 0);
        nk_volume *fv = nk_mount(argv[1], 0, err, sizeof(err));
        assert(fv);
        char flabel[64] = {0};
        assert(nk_label(fv, flabel, 64) == 0 && strcmp(flabel, lbl) == 0);
        assert(nk_create(fv, "/", "fmt.txt") == 0);
        assert(nk_write(fv, "/fmt.txt", 0, 5, "fresh") == 5);
        assert(nk_umount(fv) == 0);
    }
    printf("format ok (mkntfs x2 + remount + write)\n");
#endif
    printf("ALL BRIDGE TESTS PASSED\n");

    /* remount to prove persistence survives a full unmount */
    v = nk_mount(argv[1], 1, err, sizeof(err));
    assert(v);
    assert(nk_stat_path(v, "/t", &st) != 0);   /* cleanup persisted */
    assert(nk_umount(v) == 0);
    printf("PERSISTENCE VERIFIED\n");
    return 0;
}
