/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * BitLocker decryption layer for NTFSKit.
 *
 *   FSBlockDeviceResource  (encrypted sectors)
 *     → nk_io (pread/pwrite callbacks)
 *       → libbfio handle          [this file]
 *         → libbde_volume         (AES-XTS/CBC decrypt, unlocked by key)
 *           → decrypted NTFS bytes
 *             → ntfs_device       (bde-backed pread)
 *               → libntfs-3g mount (read-only)
 *
 * Read-only: getting files OFF a BitLocker Windows disk is the real job;
 * libbde's write path is experimental and a mistake here corrupts an
 * encrypted volume irrecoverably. Write support is a later phase.
 */
#include "ntfs_bridge.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

/* libbde bundles libbfio but doesn't install its public header; the symbols
 * live in libbde.a. bde-shim/libbfio.h supplies the opaque type so libbde.h's
 * bfio declarations (guarded by LIBBDE_HAVE_BFIO) compile. */
typedef struct libcerror_error libcerror_error_t;
#define LIBBDE_HAVE_BFIO 1
#include <libbde.h>

/* Forward-declare just the two libbfio functions we call (exact signatures
 * from libbfio_handle.h) — the symbols resolve from libbde.a. */
extern int libbfio_handle_initialize(
    libbfio_handle_t **handle, intptr_t *io_handle,
    int (*free_io_handle)(intptr_t **, libcerror_error_t **),
    int (*clone_io_handle)(intptr_t **, intptr_t *, libcerror_error_t **),
    int (*open)(intptr_t *, int, libcerror_error_t **),
    int (*close)(intptr_t *, libcerror_error_t **),
    ssize_t (*read)(intptr_t *, uint8_t *, size_t, libcerror_error_t **),
    ssize_t (*write)(intptr_t *, const uint8_t *, size_t, libcerror_error_t **),
    off64_t (*seek_offset)(intptr_t *, off64_t, int, libcerror_error_t **),
    int (*exists)(intptr_t *, libcerror_error_t **),
    int (*is_open)(intptr_t *, libcerror_error_t **),
    int (*get_size)(intptr_t *, size64_t *, libcerror_error_t **),
    uint8_t flags, libcerror_error_t **error);
extern int libbfio_handle_free(libbfio_handle_t **handle, libcerror_error_t **error);

#include <ntfs-3g/types.h>
#include <ntfs-3g/volume.h>
#include <ntfs-3g/device.h>

/* BitLocker boot sector: OEM id at 0x03 is "-FVE-FS-" (or "MSWIN4.1" for
 * BitLocker To Go, which carries an FVE signature GUID further in). We treat
 * the "-FVE-FS-" magic as the definitive marker. */
int nk_is_bitlocker(const unsigned char boot[512]) {
    static const char fve[8] = { '-','F','V','E','-','F','S','-' };
    return memcmp(boot + 3, fve, 8) == 0;
}

/* ReFS (Windows Resilient File System, incl. Win11 Dev Drive): VBR OEM id at
 * 0x03 is "ReFS\0\0\0\0" and the FSRS recognition signature is at 0x50. */
int nk_is_refs(const unsigned char boot[512]) {
    return memcmp(boot + 3, "ReFS", 4) == 0 &&
           memcmp(boot + 0x50, "FSRS", 4) == 0;
}

/* ---- libbfio handle backed by our nk_io callbacks ---- */

struct bde_bfio_ctx {
    nk_io io;
    off64_t pos;
    int open;
};

static int bfio_free(intptr_t **h, libcerror_error_t **e) {
    (void)e; if (h && *h) { free(*h); *h = NULL; } return 1;
}
static int bfio_clone(intptr_t **dst, intptr_t *src, libcerror_error_t **e) {
    (void)e;
    struct bde_bfio_ctx *c = calloc(1, sizeof(*c));
    if (!c) return -1;
    *c = *(struct bde_bfio_ctx *)src;
    *dst = (intptr_t *)c;
    return 1;
}
static int bfio_open(intptr_t *h, int flags, libcerror_error_t **e) {
    (void)flags; (void)e; ((struct bde_bfio_ctx *)h)->open = 1; return 1;
}
static int bfio_close(intptr_t *h, libcerror_error_t **e) {
    (void)e; ((struct bde_bfio_ctx *)h)->open = 0; return 0;
}
static ssize_t bfio_read(intptr_t *h, uint8_t *buf, size_t size, libcerror_error_t **e) {
    (void)e;
    struct bde_bfio_ctx *c = (struct bde_bfio_ctx *)h;
    long long n = c->io.pread(c->io.ctx, buf, (long long)size, (long long)c->pos);
    if (n < 0) return -1;
    c->pos += n;
    return (ssize_t)n;
}
static ssize_t bfio_write(intptr_t *h, const uint8_t *buf, size_t size, libcerror_error_t **e) {
    (void)h; (void)buf; (void)size; (void)e; errno = EROFS; return -1;   /* RO */
}
static off64_t bfio_seek(intptr_t *h, off64_t off, int whence, libcerror_error_t **e) {
    (void)e;
    struct bde_bfio_ctx *c = (struct bde_bfio_ctx *)h;
    off64_t base = whence == SEEK_SET ? 0 : whence == SEEK_CUR ? c->pos : c->io.size;
    if (base + off < 0) return -1;
    c->pos = base + off;
    return c->pos;
}
static int bfio_exists(intptr_t *h, libcerror_error_t **e) { (void)h; (void)e; return 1; }
static int bfio_is_open(intptr_t *h, libcerror_error_t **e) {
    (void)e; return ((struct bde_bfio_ctx *)h)->open;
}
static int bfio_get_size(intptr_t *h, size64_t *size, libcerror_error_t **e) {
    (void)e; *size = (size64_t)((struct bde_bfio_ctx *)h)->io.size; return 1;
}

/* ---- ntfs_device backed by a decrypted libbde_volume ---- */

struct bde_dev {
    libbde_volume_t *vol;
    off64_t pos;
    size64_t size;
};

static int bdedev_open(struct ntfs_device *dev, int flags) {
    NDevSetOpen(dev); NDevSetReadOnly(dev); (void)flags; return 0;
}
static int bdedev_close(struct ntfs_device *dev) { NDevClearOpen(dev); return 0; }
static s64 bdedev_seek(struct ntfs_device *dev, s64 offset, int whence) {
    struct bde_dev *d = dev->d_private;
    s64 base = whence == SEEK_SET ? 0 : whence == SEEK_CUR ? d->pos : (s64)d->size;
    if (base + offset < 0) { errno = EINVAL; return -1; }
    d->pos = base + offset;
    return d->pos;
}
static s64 bdedev_pread(struct ntfs_device *dev, void *buf, s64 count, s64 offset) {
    struct bde_dev *d = dev->d_private;
    ssize_t n = libbde_volume_read_buffer_at_offset(d->vol, buf, (size_t)count,
                                                    (off64_t)offset, NULL);
    if (n < 0) { errno = EIO; return -1; }
    return (s64)n;
}
static s64 bdedev_pwrite(struct ntfs_device *dev, const void *b, s64 c, s64 o) {
    (void)dev; (void)b; (void)c; (void)o; errno = EROFS; return -1;
}
static s64 bdedev_read(struct ntfs_device *dev, void *buf, s64 count) {
    struct bde_dev *d = dev->d_private;
    s64 n = bdedev_pread(dev, buf, count, d->pos);
    if (n > 0) d->pos += n;
    return n;
}
static s64 bdedev_write(struct ntfs_device *dev, const void *b, s64 c) {
    (void)dev; (void)b; (void)c; errno = EROFS; return -1;
}
static int bdedev_sync(struct ntfs_device *dev) { (void)dev; return 0; }
static int bdedev_stat(struct ntfs_device *dev, struct stat *st) {
    struct bde_dev *d = dev->d_private;
    memset(st, 0, sizeof(*st));
    st->st_mode = S_IFREG | 0400;
    st->st_size = (off_t)d->size;
    return 0;
}
static int bdedev_ioctl(struct ntfs_device *dev, unsigned long r, void *a) {
    (void)dev; (void)r; (void)a; errno = ENOTSUP; return -1;
}
static struct ntfs_device_operations bde_dev_ops = {
    .open = bdedev_open, .close = bdedev_close, .seek = bdedev_seek,
    .read = bdedev_read, .write = bdedev_write, .pread = bdedev_pread,
    .pwrite = bdedev_pwrite, .sync = bdedev_sync, .stat = bdedev_stat,
    .ioctl = bdedev_ioctl,
};

/* Opaque returned to Swift so it can free the whole chain on unmount. */
struct nk_bde {
    libbfio_handle_t *bfio;
    struct bde_bfio_ctx *bctx;
    libbde_volume_t *vol;
    struct bde_dev *dev;      /* d_private of the ntfs_device */
};

/* Build the decrypted device. cred is a BitLocker recovery password
 * ("xxxxxx-xxxxxx-…", 48 digits in 8 groups) or a user password, selected by
 * cred_kind. Returns a device libntfs-3g can mount, or NULL; *out keeps the
 * chain alive until nk_bde_free. */
struct ntfs_device *nk_bde_open(const nk_io *io, const char *cred, int cred_kind,
                                struct nk_bde **out, char *errbuf, size_t errlen) {
    if (!io || !cred) return NULL;
    struct nk_bde *b = calloc(1, sizeof(*b));
    struct bde_bfio_ctx *bctx = calloc(1, sizeof(*bctx));
    if (!b || !bctx) { free(b); free(bctx); return NULL; }
    bctx->io = *io;

    if (libbfio_handle_initialize((libbfio_handle_t **)&b->bfio, (intptr_t *)bctx,
            bfio_free, bfio_clone, bfio_open, bfio_close, bfio_read, bfio_write,
            bfio_seek, bfio_exists, bfio_is_open, bfio_get_size, 0, NULL) != 1) {
        free(bctx); free(b); return NULL;
    }
    b->bctx = bctx;   /* freed by libbfio via bfio_free */

    if (libbde_volume_initialize(&b->vol, NULL) != 1) goto fail;
    if (libbde_volume_open_file_io_handle(b->vol, b->bfio, LIBBDE_OPEN_READ, NULL) != 1) {
        if (errbuf && errlen) snprintf(errbuf, errlen, "not a BitLocker volume");
        goto fail;
    }
    /* Supply the credential, then unlock. */
    size_t clen = strlen(cred);
    if (cred_kind == NK_BDE_RECOVERY)
        libbde_volume_set_utf8_recovery_password(b->vol, (const uint8_t *)cred, clen, NULL);
    else
        libbde_volume_set_utf8_password(b->vol, (const uint8_t *)cred, clen, NULL);

    if (libbde_volume_unlock(b->vol, NULL) != 1 ||
        libbde_volume_is_locked(b->vol, NULL) != 0) {
        if (errbuf && errlen) snprintf(errbuf, errlen, "wrong BitLocker key");
        goto fail;
    }

    struct bde_dev *d = calloc(1, sizeof(*d));
    if (!d) goto fail;
    d->vol = b->vol;
    libbde_volume_get_size(b->vol, &d->size, NULL);
    b->dev = d;

    struct ntfs_device *dev = ntfs_device_alloc("bitlocker", 0, &bde_dev_ops, d);
    if (!dev) { free(d); b->dev = NULL; goto fail; }
    *out = b;
    return dev;

fail:
    if (b->vol) { libbde_volume_free(&b->vol, NULL); }
    if (b->bfio) { libbfio_handle_free(&b->bfio, NULL); }
    free(b);
    return NULL;
}

void nk_bde_free(struct nk_bde *b) {
    if (!b) return;
    if (b->vol) libbde_volume_free(&b->vol, NULL);
    if (b->bfio) libbfio_handle_free(&b->bfio, NULL);
    free(b->dev);
    free(b);
}
