/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "ntfs_bridge.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include <ntfs-3g/types.h>
#include <ntfs-3g/layout.h>
#include <ntfs-3g/volume.h>
#include <ntfs-3g/inode.h>
#include <ntfs-3g/dir.h>
#include <ntfs-3g/attrib.h>
#include <ntfs-3g/unistr.h>
#include <ntfs-3g/ntfstime.h>
#include <ntfs-3g/device.h>
#include <ntfs-3g/reparse.h>
#include <ntfs-3g/runlist.h>

struct nk_bde;   /* BitLocker decryption chain, defined in nk_bde.c */
struct ntfs_device *nk_bde_open(const nk_io *io, const char *cred, int cred_kind,
                                struct nk_bde **out, char *errbuf, size_t errlen);
void nk_bde_free(struct nk_bde *b);

struct nk_volume {
    ntfs_volume *vol;
    void *devctx;        /* nk_devctx when mounted via nk_mount_io */
    struct nk_bde *bde;  /* BitLocker chain when mounted encrypted */
};

/* ---- callback-backed ntfs_device ---- */

struct nk_devctx {
    nk_io io;
    s64   pos;
};

static int nkdev_open(struct ntfs_device *dev, int flags) {
    if ((flags & O_ACCMODE) == O_RDONLY)
        NDevSetReadOnly(dev);
    NDevSetOpen(dev);
    return 0;
}

static int nkdev_close(struct ntfs_device *dev) {
    NDevClearOpen(dev);
    return 0;
}

static s64 nkdev_seek(struct ntfs_device *dev, s64 offset, int whence) {
    struct nk_devctx *c = dev->d_private;
    s64 base = whence == SEEK_SET ? 0 :
               whence == SEEK_CUR ? c->pos : c->io.size;
    if (base + offset < 0) { errno = EINVAL; return -1; }
    c->pos = base + offset;
    return c->pos;
}

static s64 nkdev_pread(struct ntfs_device *dev, void *buf, s64 count, s64 offset) {
    struct nk_devctx *c = dev->d_private;
    s64 n = c->io.pread(c->io.ctx, buf, count, offset);
    if (n < 0) { errno = EIO; return -1; }
    return n;
}

static s64 nkdev_pwrite(struct ntfs_device *dev, const void *buf, s64 count, s64 offset) {
    struct nk_devctx *c = dev->d_private;
    if (NDevReadOnly(dev)) { errno = EROFS; return -1; }
    s64 n = c->io.pwrite(c->io.ctx, buf, count, offset);
    if (n < 0) { errno = EIO; return -1; }
    NDevSetDirty(dev);
    return n;
}

static s64 nkdev_read(struct ntfs_device *dev, void *buf, s64 count) {
    struct nk_devctx *c = dev->d_private;
    s64 n = nkdev_pread(dev, buf, count, c->pos);
    if (n > 0) c->pos += n;
    return n;
}

static s64 nkdev_write(struct ntfs_device *dev, const void *buf, s64 count) {
    struct nk_devctx *c = dev->d_private;
    s64 n = nkdev_pwrite(dev, buf, count, c->pos);
    if (n > 0) c->pos += n;
    return n;
}

static int nkdev_sync(struct ntfs_device *dev) {
    NDevClearDirty(dev);
    return 0;
}

static int nkdev_stat(struct ntfs_device *dev, struct stat *buf) {
    struct nk_devctx *c = dev->d_private;
    memset(buf, 0, sizeof(*buf));
    buf->st_mode = S_IFREG | 0600;   /* image-file semantics: no ioctls */
    buf->st_size = c->io.size;
    return 0;
}

static int nkdev_ioctl(struct ntfs_device *dev, unsigned long request, void *argp) {
    (void)dev; (void)request; (void)argp;
    errno = ENOTSUP;
    return -1;
}

static struct ntfs_device_operations nk_dev_ops = {
    .open   = nkdev_open,
    .close  = nkdev_close,
    .seek   = nkdev_seek,
    .read   = nkdev_read,
    .write  = nkdev_write,
    .pread  = nkdev_pread,
    .pwrite = nkdev_pwrite,
    .sync   = nkdev_sync,
    .stat   = nkdev_stat,
    .ioctl  = nkdev_ioctl,
};

nk_volume *nk_mount_io(const nk_io *io, char *errbuf, size_t errlen) {
    struct nk_devctx *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->io = *io;

    struct ntfs_device *dev = ntfs_device_alloc("fskit-block", 0, &nk_dev_ops, c);
    if (!dev) { free(c); return NULL; }

    ntfs_mount_flags flags = io->readonly ? NTFS_MNT_RDONLY : NTFS_MNT_RECOVER;
    ntfs_volume *vol = ntfs_device_mount(dev, flags);
    if (!vol) {
        if (errbuf && errlen)
            snprintf(errbuf, errlen, "ntfs_device_mount: %s", strerror(errno));
        ntfs_device_free(dev);
        free(c);
        return NULL;
    }
    nk_volume *v = calloc(1, sizeof(*v));
    if (!v) { ntfs_umount(vol, TRUE); free(c); return NULL; }
    v->vol = vol;
    v->devctx = c;
    return v;
}

nk_volume *nk_mount(const char *path, int readonly, char *errbuf, size_t errlen) {
    /* NTFS_MNT_RECOVER replays a dirty $LogFile (Windows unclean shutdown)
     * the same way ntfs-3g's FUSE front end does by default. */
    ntfs_mount_flags flags = readonly ? NTFS_MNT_RDONLY : NTFS_MNT_RECOVER;
    ntfs_volume *vol = ntfs_mount(path, flags);
    if (!vol) {
        if (errbuf && errlen)
            snprintf(errbuf, errlen, "ntfs_mount(%s): %s", path, strerror(errno));
        return NULL;
    }
    nk_volume *v = calloc(1, sizeof(*v));
    if (!v) { ntfs_umount(vol, TRUE); return NULL; }
    v->vol = vol;
    return v;
}

int nk_umount(nk_volume *v) {
    if (!v) return -1;
    int r = v->vol ? ntfs_umount(v->vol, FALSE) : 0;  /* frees the device too */
    free(v->devctx);
    if (v->bde) nk_bde_free(v->bde);   /* tears down libbde + libbfio */
    free(v);
    return r;
}

nk_volume *nk_mount_bitlocker(const nk_io *io, const char *cred, int cred_kind,
                              char *errbuf, size_t errlen) {
    if (!io || !cred) return NULL;
    struct nk_bde *bde = NULL;
    struct ntfs_device *dev = nk_bde_open(io, cred, cred_kind, &bde, errbuf, errlen);
    if (!dev) return NULL;   /* errbuf set by nk_bde_open */

    /* Decrypted stream is read-only; recover the journal in memory only. */
    ntfs_volume *vol = ntfs_device_mount(dev, NTFS_MNT_RDONLY);
    if (!vol) {
        if (errbuf && errlen)
            snprintf(errbuf, errlen, "decrypted, but not NTFS: %s", strerror(errno));
        ntfs_device_free(dev);
        nk_bde_free(bde);
        return NULL;
    }
    nk_volume *v = calloc(1, sizeof(*v));
    if (!v) { ntfs_umount(vol, TRUE); nk_bde_free(bde); return NULL; }
    v->vol = vol;
    v->bde = bde;
    return v;
}

int nk_statvfs(nk_volume *v, long long *total_bytes, long long *free_bytes,
               int *cluster_size) {
    if (!v) return -1;
    ntfs_volume *vol = v->vol;
    if (ntfs_volume_get_free_space(vol) < 0) return -1;
    if (total_bytes)  *total_bytes  = (long long)vol->nr_clusters * vol->cluster_size;
    if (free_bytes)   *free_bytes   = (long long)vol->free_clusters * vol->cluster_size;
    if (cluster_size) *cluster_size = (int)vol->cluster_size;
    return 0;
}

int nk_label(nk_volume *v, char *buf, size_t buflen) {
    if (!v || !buf || buflen == 0) return -1;
    const char *name = v->vol->vol_name;
    snprintf(buf, buflen, "%s", name ? name : "");
    return 0;
}

/* Interix-style symlink: SYSTEM file whose data starts with "IntxLNK\1"
 * (the format ntfs_create_symlink writes, same as ntfs-3g's FUSE driver). */
static int is_intx_symlink(ntfs_attr *na) {
    if (!na || na->data_size < 10 || na->data_size > 4096 + 8) return 0;
    le64 magic = 0;
    if (ntfs_attr_pread(na, 0, sizeof(magic), &magic) != sizeof(magic)) return 0;
    return magic == INTX_SYMBOLIC_LINK;
}

static void fill_stat(ntfs_inode *ni, ntfs_attr *na, nk_stat *st) {
    memset(st, 0, sizeof(*st));
    st->is_dir = (ni->mrec->flags & MFT_RECORD_IS_DIRECTORY) ? 1 : 0;
    st->inode = (uint64_t)ni->mft_no;
    st->is_symlink = (ni->flags & FILE_ATTR_REPARSE_POINT) ? 1 : 0;
    if (!st->is_symlink && (ni->flags & FILE_ATTR_SYSTEM) && is_intx_symlink(na))
        st->is_symlink = 1;
    if (na) {
        st->size = (long long)na->data_size;
        st->alloc_size = (long long)na->allocated_size;
        st->is_resident = NAttrNonResident(na) ? 0 : 1;
        /* Compressed/encrypted data can't be mapped for the kernel — those go
         * through the byte-copy path. Resident files convert to non-resident
         * in nk_blockmap; sparse holes pack as zero-fill extents. */
        st->koio_ok = !(na->data_flags & (ATTR_IS_COMPRESSED | ATTR_IS_ENCRYPTED)) &&
                      !st->is_symlink;
    }
    st->atime = ntfs2timespec(ni->last_access_time).tv_sec;
    st->mtime = ntfs2timespec(ni->last_data_change_time).tv_sec;
    st->ctime = ntfs2timespec(ni->last_mft_change_time).tv_sec;
    st->btime = ntfs2timespec(ni->creation_time).tv_sec;
}

int nk_stat_path(nk_volume *v, const char *path, nk_stat *st) {
    if (!v || !st) return -1;
    ntfs_inode *ni = ntfs_pathname_to_inode(v->vol, NULL, path);
    if (!ni) return -1;
    ntfs_attr *na = NULL;
    if (!(ni->mrec->flags & MFT_RECORD_IS_DIRECTORY))
        na = ntfs_attr_open(ni, AT_DATA, AT_UNNAMED, 0);
    fill_stat(ni, na, st);
    if (na) ntfs_attr_close(na);
    ntfs_inode_close(ni);
    return 0;
}

struct list_ctx {
    nk_volume   *v;
    nk_dirent_cb cb;
    void        *ctx;
    int          stop;
};

static int nk_filldir(void *ctx, const ntfschar *name, const int name_len,
                      const int name_type, const s64 pos, const MFT_REF mref,
                      const unsigned dt_type) {
    (void)pos;
    struct list_ctx *lc = ctx;
    if (lc->stop) return 0;
    if (name_type == FILE_NAME_DOS) return 0;          /* skip 8.3 aliases */
    if (MREF(mref) < (u64)FILE_first_user) return 0;   /* skip $MFT & friends */

    char *utf8 = NULL;
    if (ntfs_ucstombs(name, name_len, &utf8, 0) < 0 || !utf8) return 0;

    int is_dot = utf8[0] == '.' &&
                 (utf8[1] == '\0' || (utf8[1] == '.' && utf8[2] == '\0'));
    if (!is_dot) {
        nk_dirent e = { .name = utf8, .is_dir = dt_type == NTFS_DT_DIR,
                        .size = 0, .inode = MREF(mref) };
        if (!e.is_dir) {
            ntfs_inode *ni = ntfs_inode_open(lc->v->vol, mref);
            if (ni) {
                ntfs_attr *na = ntfs_attr_open(ni, AT_DATA, AT_UNNAMED, 0);
                if (na) { e.size = (long long)na->data_size; ntfs_attr_close(na); }
                ntfs_inode_close(ni);
            }
        }
        if (lc->cb(lc->ctx, &e) != 0) lc->stop = 1;
    }
    free(utf8);
    return 0;
}

int nk_list(nk_volume *v, const char *dir_path, nk_dirent_cb cb, void *ctx) {
    if (!v || !cb) return -1;
    ntfs_inode *dir = ntfs_pathname_to_inode(v->vol, NULL, dir_path);
    if (!dir) return -1;
    struct list_ctx lc = { v, cb, ctx, 0 };
    s64 pos = 0;
    int r = ntfs_readdir(dir, &pos, &lc, nk_filldir);
    ntfs_inode_close(dir);
    return r ? -1 : 0;
}

long long nk_read(nk_volume *v, const char *path, long long offset,
                  long long count, void *buf) {
    if (!v) return -1;
    ntfs_inode *ni = ntfs_pathname_to_inode(v->vol, NULL, path);
    if (!ni) return -1;
    long long n = -1;
    ntfs_attr *na = ntfs_attr_open(ni, AT_DATA, AT_UNNAMED, 0);
    if (na) {
        n = (long long)ntfs_attr_pread(na, offset, count, buf);
        ntfs_attr_close(na);
    }
    ntfs_inode_close(ni);
    return n;
}

long long nk_write(nk_volume *v, const char *path, long long offset,
                   long long count, const void *buf) {
    if (!v) return -1;
    ntfs_inode *ni = ntfs_pathname_to_inode(v->vol, NULL, path);
    if (!ni) return -1;
    long long n = -1;
    ntfs_attr *na = ntfs_attr_open(ni, AT_DATA, AT_UNNAMED, 0);
    if (na) {
        n = (long long)ntfs_attr_pwrite(na, offset, count, buf);
        ntfs_attr_close(na);
    }
    ntfs_inode_update_times(ni, NTFS_UPDATE_MCTIME);
    ntfs_inode_close(ni);   /* flushes size/timestamps */
    return n;
}

static int create_node(nk_volume *v, const char *dir_path, const char *name,
                       mode_t type) {
    if (!v) return -1;
    ntfs_inode *dir = ntfs_pathname_to_inode(v->vol, NULL, dir_path);
    if (!dir) return -1;
    ntfschar *ucs = NULL;
    int len = ntfs_mbstoucs(name, &ucs);
    /* NTFS names are at most 255 UCS-2 units; (u8) casts must never wrap. */
    if (len <= 0 || len > 255 || !ucs) { free(ucs); ntfs_inode_close(dir); return -1; }
    ntfs_inode *ni = ntfs_create(dir, const_cpu_to_le32(0), ucs, (u8)len, type);
    free(ucs);
    int r = ni ? 0 : -1;
    if (ni) ntfs_inode_close(ni);
    ntfs_inode_close(dir);
    return r;
}

int nk_create(nk_volume *v, const char *dir_path, const char *name) {
    return create_node(v, dir_path, name, S_IFREG);
}

int nk_mkdir(nk_volume *v, const char *dir_path, const char *name) {
    return create_node(v, dir_path, name, S_IFDIR);
}

/* Split "/a/b/c" into parent "/a/b" (written into parent[]) and leaf "c". */
static const char *split_path(const char *path, char *parent, size_t plen_max) {
    const char *slash = strrchr(path, '/');
    if (!slash) return NULL;
    size_t plen = (size_t)(slash - path);
    if (plen == 0) { strcpy(parent, "/"); }
    else {
        if (plen >= plen_max) return NULL;
        memcpy(parent, path, plen);
        parent[plen] = '\0';
    }
    return slash + 1;
}

int nk_delete(nk_volume *v, const char *path) {
    if (!v) return -1;
    char parent[4096];
    const char *leaf = split_path(path, parent, sizeof(parent));
    if (!leaf) return -1;

    ntfs_inode *ni = ntfs_pathname_to_inode(v->vol, NULL, path);
    if (!ni) return -1;
    ntfs_inode *dir = ntfs_pathname_to_inode(v->vol, NULL, parent);
    if (!dir) { ntfs_inode_close(ni); return -1; }

    ntfschar *ucs = NULL;
    int len = ntfs_mbstoucs(leaf, &ucs);
    if (len <= 0 || len > 255 || !ucs) {
        free(ucs); ntfs_inode_close(dir); ntfs_inode_close(ni); return -1;
    }

    /* ntfs_delete consumes (closes) both inodes, success or failure. */
    int r = ntfs_delete(v->vol, path, ni, dir, ucs, (u8)len);
    free(ucs);
    return r ? -1 : 0;
}

/* Rename the way ntfs-3g's FUSE front end does: link under the new name,
 * then delete the old name. Works for files and directories. */
int nk_rename(nk_volume *v, const char *old_path, const char *new_dir,
              const char *new_name) {
    if (!v) return -1;

    ntfs_inode *ni = ntfs_pathname_to_inode(v->vol, NULL, old_path);
    if (!ni) return -1;
    ntfs_inode *dir = ntfs_pathname_to_inode(v->vol, NULL, new_dir);
    if (!dir) { ntfs_inode_close(ni); return -1; }

    ntfschar *ucs = NULL;
    int len = ntfs_mbstoucs(new_name, &ucs);
    if (len <= 0 || len > 255 || !ucs) {
        free(ucs); ntfs_inode_close(dir); ntfs_inode_close(ni); return -1;
    }

    int r = ntfs_link(ni, dir, ucs, (u8)len);
    ntfs_inode_close(dir);
    ntfs_inode_close(ni);
    if (r) { free(ucs); return -1; }

    if (nk_delete(v, old_path) == 0) { free(ucs); return 0; }

    /* Deleting the old name failed — roll back the new link so the namespace
     * isn't left with two names for one file. */
    char ndir_buf[4096];
    snprintf(ndir_buf, sizeof(ndir_buf), "%s/%s",
             strcmp(new_dir, "/") == 0 ? "" : new_dir, new_name);
    ntfs_inode *nni = ntfs_pathname_to_inode(v->vol, NULL, ndir_buf);
    ntfs_inode *ndir = ntfs_pathname_to_inode(v->vol, NULL, new_dir);
    if (nni && ndir)
        ntfs_delete(v->vol, ndir_buf, nni, ndir, ucs, (u8)len);  /* consumes both */
    else {
        if (nni) ntfs_inode_close(nni);
        if (ndir) ntfs_inode_close(ndir);
    }
    free(ucs);
    return -1;
}

int nk_truncate(nk_volume *v, const char *path, long long size) {
    if (!v) return -1;
    ntfs_inode *ni = ntfs_pathname_to_inode(v->vol, NULL, path);
    if (!ni) return -1;
    int r = -1;
    ntfs_attr *na = ntfs_attr_open(ni, AT_DATA, AT_UNNAMED, 0);
    if (na) {
        r = ntfs_attr_truncate(na, size);
        ntfs_attr_close(na);
    }
    ntfs_inode_update_times(ni, NTFS_UPDATE_MCTIME);
    ntfs_inode_close(ni);
    return r ? -1 : 0;
}

int nk_sync(nk_volume *v) {
    if (!v) return -1;
    return ntfs_device_sync(v->vol->dev) ? -1 : 0;
}

int nk_set_times(nk_volume *v, const char *path, long long atime,
                 long long mtime, long long btime) {
    if (!v) return -1;
    ntfs_inode *ni = ntfs_pathname_to_inode(v->vol, NULL, path);
    if (!ni) return -1;
    struct timespec ts = { 0, 0 };
    if (atime >= 0) { ts.tv_sec = (time_t)atime; ni->last_access_time = timespec2ntfs(ts); }
    if (mtime >= 0) { ts.tv_sec = (time_t)mtime; ni->last_data_change_time = timespec2ntfs(ts); }
    if (btime >= 0) { ts.tv_sec = (time_t)btime; ni->creation_time = timespec2ntfs(ts); }
    NInoFileNameSetDirty(ni);
    ntfs_inode_mark_dirty(ni);
    ntfs_inode_close(ni);
    return 0;
}

int nk_readlink(nk_volume *v, const char *path, char *buf, size_t buflen) {
    if (!v || !buf || buflen == 0) return -1;
    ntfs_inode *ni = ntfs_pathname_to_inode(v->vol, NULL, path);
    if (!ni) return -1;
    int r = -1;
    if (ni->flags & FILE_ATTR_REPARSE_POINT) {
        char *target = ntfs_make_symlink(ni, "/");
        if (target) {
            snprintf(buf, buflen, "%s", target);
            free(target);
            r = 0;
        }
    } else {
        /* Interix symlink: UCS-2 target follows the 8-byte IntxLNK magic. */
        ntfs_attr *na = ntfs_attr_open(ni, AT_DATA, AT_UNNAMED, 0);
        if (na && is_intx_symlink(na)) {
            s64 tlen_bytes = na->data_size - 8;
            ntfschar *ucs = malloc((size_t)tlen_bytes);
            if (ucs && ntfs_attr_pread(na, 8, tlen_bytes, ucs) == tlen_bytes) {
                char *utf8 = NULL;
                if (ntfs_ucstombs(ucs, (int)(tlen_bytes / 2), &utf8, 0) >= 0 && utf8) {
                    snprintf(buf, buflen, "%s", utf8);
                    free(utf8);
                    r = 0;
                }
            }
            free(ucs);
        }
        if (na) ntfs_attr_close(na);
    }
    ntfs_inode_close(ni);
    return r;
}

int nk_create_symlink(nk_volume *v, const char *dir_path, const char *name,
                      const char *target) {
    if (!v) return -1;
    ntfs_inode *dir = ntfs_pathname_to_inode(v->vol, NULL, dir_path);
    if (!dir) return -1;
    ntfschar *uname = NULL, *utarget = NULL;
    int nlen = ntfs_mbstoucs(name, &uname);
    int tlen = ntfs_mbstoucs(target, &utarget);
    int r = -1;
    if (nlen > 0 && nlen <= 255 && tlen > 0) {
        ntfs_inode *ni = ntfs_create_symlink(dir, const_cpu_to_le32(0),
                                             uname, (u8)nlen, utarget, tlen);
        if (ni) { ntfs_inode_close(ni); r = 0; }
    }
    free(uname);
    free(utarget);
    ntfs_inode_close(dir);
    return r;
}

int nk_is_dirty(nk_volume *v) {
    if (!v) return -1;
    return (v->vol->flags & VOLUME_IS_DIRTY) ? 1 : 0;
}

static int bad_runlist(ntfs_volume *vol, const runlist_element *rl);

int nk_blockmap(nk_volume *v, const char *path, long long offset,
                long long length, int for_write, int blocksize,
                nk_extent_cb cb, void *ctx) {
    if (!v || !cb) return -1;
    /* offset/length come from the kernel but sanity-check anyway: negative or
     * wrapping windows must never reach truncate/extent math. */
    if (offset < 0 || length <= 0 || offset > INT64_MAX - length) return -1;
    s64 bs = blocksize >= 512 ? blocksize : 512;
    ntfs_inode *ni = ntfs_pathname_to_inode(v->vol, NULL, path);
    if (!ni) return -1;
    ntfs_attr *na = ntfs_attr_open(ni, AT_DATA, AT_UNNAMED, 0);
    if (!na) { ntfs_inode_close(ni); return -1; }

    int r = 0;
    if (na->data_flags & (ATTR_IS_COMPRESSED | ATTR_IS_ENCRYPTED)) {
        r = -2;   /* not mappable — caller must use the byte-copy path */
        goto out;
    }
    /* Resident data (small/new files) lives inside the MFT record and has no
     * clusters to map. Convert to non-resident so the kernel gets real
     * extents — costs one cluster per small file, buys 100% KOIO coverage.
     * Conversion is a WRITE: on a read-only volume it can't happen, so report
     * unmappable (the host inhibits KOIO for resident files on RO mounts). */
    if (!NAttrNonResident(na)) {
        if (NVolReadOnly(v->vol) || ntfs_attr_force_non_resident(na)) {
            r = -2;
            goto out;
        }
    }
    /* Writes past the current allocation grow the file with SOLID clusters
     * (allocated, not sparse) so the kernel has real sectors to write into —
     * without the engine writing a single data byte. initialized_size stays
     * behind; nk_complete_write advances it once the kernel's write lands, and
     * until then reads of the region map as zero-fill (correct: unwritten). */
    if (for_write && offset + length > na->data_size) {
        if (ntfs_attr_truncate_solid(na, offset + length)) { r = -1; goto out; }
    }
    if (ntfs_attr_map_whole_runlist(na)) { r = -1; goto out; }
    if (bad_runlist(v->vol, na->rl)) { r = -1; goto out; }

    /* Pre-existing sparse holes inside the write window still need real
     * clusters. ntfs_attr_pwrite REALLOCATES na->rl while allocating, so never
     * keep iterating a runlist across a pwrite: find the first overlapping
     * hole, fill it, re-map, and scan again from scratch. (Sequential writes
     * never hit this — only writes into the middle of sparse files do.) */
    if (for_write) {
        s64 csize = v->vol->cluster_size;
        static const char zeros[65536];
        for (;;) {
            s64 start = -1, end = -1;
            for (runlist_element *rl = na->rl; rl && rl->length; rl++) {
                if (rl->lcn != LCN_HOLE) continue;
                s64 log = rl->vcn * csize, len = rl->length * csize;
                s64 s = log > offset ? log : offset;
                s64 e = (log + len) < (offset + length) ? (log + len) : (offset + length);
                if (e > s) { start = s; end = e; break; }
            }
            if (start < 0) break;
            for (s64 p = start; p < end; p += (s64)sizeof(zeros)) {
                s64 chunk = (end - p) < (s64)sizeof(zeros) ? (end - p) : (s64)sizeof(zeros);
                if (ntfs_attr_pwrite(na, p, chunk, zeros) != chunk) { r = -1; goto out; }
            }
            if (ntfs_attr_map_whole_runlist(na)) { r = -1; goto out; }
            if (bad_runlist(v->vol, na->rl)) { r = -1; goto out; }
        }
    }

    s64 csize = v->vol->cluster_size;
    /* Bytes past initialized_size read as zeros by contract — mapping them as
     * data would leak stale cluster contents to userspace. Extents handed to
     * the kernel must stay block-aligned; initialized_size is byte-granular,
     * so zero the partial block ON DISK first, then split at the rounded-up
     * boundary — nothing stale is ever exposed. */
    s64 init_end = INT64_MAX;
    if (!for_write) {
        init_end = na->initialized_size;
        if (init_end < 0) { r = -1; goto out; }
        if (init_end % bs) {
            s64 zend = init_end + (bs - init_end % bs);
            if (zend > na->data_size) zend = na->data_size;
            if (zend > init_end && !NVolReadOnly(v->vol)) {
                static const char zpad[4096];
                s64 p = init_end;
                while (p < zend) {
                    s64 chunk = (zend - p) < (s64)sizeof(zpad) ? (zend - p)
                                                               : (s64)sizeof(zpad);
                    if (ntfs_attr_pwrite(na, p, chunk, zpad) != chunk) {
                        r = -1;
                        goto out;
                    }
                    p += chunk;
                }
                if (ntfs_attr_map_whole_runlist(na) ||
                    bad_runlist(v->vol, na->rl)) { r = -1; goto out; }
                init_end = na->initialized_size;
            }
            init_end = ((init_end + bs - 1) / bs) * bs;
        }
    }

    s64 covered = offset;
    for (runlist_element *rl = na->rl; rl && rl->length; rl++) {
        s64 log = rl->vcn * csize;
        s64 len = rl->length * csize;
        s64 phys = rl->lcn >= 0 ? rl->lcn * csize : -1;
        s64 start = log > offset ? log : offset;
        s64 end_req = offset + length;
        s64 end = (log + len) < end_req ? (log + len) : end_req;
        if (end <= start) continue;
        if (phys >= 0 && start < init_end && end > init_end) {
            /* straddles initialized_size: real data below, zeros above */
            if (cb(ctx, start, phys + (start - log), init_end - start))
                goto out;
            if (cb(ctx, init_end, -1, end - init_end))
                goto out;
            covered = end;
            continue;
        }
        int as_zero = phys < 0 || start >= init_end;
        if (cb(ctx, start, as_zero ? -1 : phys + (start - log), end - start))
            goto out;
        covered = end;
    }
    /* A short map is undefined kernel behavior. Writes must be fully backed by
     * real clusters; reads past the last run (sparse/EOF tail) are zeros. */
    if (covered < offset + length) {
        if (for_write)
            r = -1;
        else
            cb(ctx, covered, -1, offset + length - covered);
    }
out:
    ntfs_attr_close(na);
    /* flush metadata (runlist growth) before the kernel touches those blocks */
    if (ntfs_inode_sync(ni) && r == 0) r = -1;
    if (ntfs_inode_close(ni) && r == 0) r = -1;
    return r;
}

/* Untrusted on-disk runlists: reject anything whose math would overflow,
 * whose clusters fall outside the volume, or whose VCNs aren't contiguous
 * (a VCN gap would silently drop coverage mid-window). */
static int bad_runlist(ntfs_volume *vol, const runlist_element *rl) {
    s64 csize = vol->cluster_size;
    s64 expect_vcn = -1;
    for (; rl && rl->length; rl++) {
        if (rl->lcn < LCN_HOLE) return 1;            /* unmapped after map_whole */
        if (rl->length <= 0 || rl->vcn < 0 ||
            rl->vcn > INT64_MAX / csize || rl->length > INT64_MAX / csize)
            return 1;
        if (rl->lcn >= 0 &&
            (rl->lcn >= vol->nr_clusters || rl->lcn > INT64_MAX / csize ||
             rl->length > vol->nr_clusters - rl->lcn))
            return 1;
        if (expect_vcn >= 0 && rl->vcn != expect_vcn) return 1;
        expect_vcn = rl->vcn + rl->length;
    }
    return 0;
}

/* Called after the kernel reports a successful KOIO write of
 * [offset, offset+length): make those bytes officially initialized. Any gap
 * of allocated-but-unwritten bytes below the window is zeroed on disk first
 * (sequential writes have no gap). */
int nk_complete_write(nk_volume *v, const char *path, long long offset,
                      long long length) {
    if (!v || offset < 0 || length <= 0 || offset > INT64_MAX - length)
        return -1;
    ntfs_inode *ni = ntfs_pathname_to_inode(v->vol, NULL, path);
    if (!ni) return -1;
    int r = 0;
    ntfs_attr *na = ntfs_attr_open(ni, AT_DATA, AT_UNNAMED, 0);
    if (!na) { ntfs_inode_close(ni); return -1; }

    s64 target = offset + length;
    if (target > na->data_size) target = na->data_size;
    if (NAttrNonResident(na) && na->initialized_size < target) {
        if (na->initialized_size < offset) {
            /* zero the unwritten gap below the window (advances init size) */
            static const char zeros[65536];
            s64 p = na->initialized_size;
            while (p < offset) {
                s64 chunk = (offset - p) < (s64)sizeof(zeros) ? (offset - p)
                                                              : (s64)sizeof(zeros);
                if (ntfs_attr_pwrite(na, p, chunk, zeros) != chunk) {
                    r = -1;
                    goto done;
                }
                p += chunk;
            }
        }
        /* Stamp the new initialized_size straight into the attribute record —
         * the kernel already put the data on disk, we only own the metadata. */
        ntfs_attr_search_ctx *sctx = ntfs_attr_get_search_ctx(na->ni, NULL);
        if (!sctx) { r = -1; goto done; }
        if (ntfs_attr_lookup(na->type, na->name, na->name_len, CASE_SENSITIVE,
                             0, NULL, 0, sctx)) {
            ntfs_attr_put_search_ctx(sctx);
            r = -1;
            goto done;
        }
        sctx->attr->initialized_size = cpu_to_sle64(target);
        na->initialized_size = target;
        ntfs_inode_mark_dirty(sctx->ntfs_ino);
        ntfs_attr_put_search_ctx(sctx);
    }
done:
    ntfs_attr_close(na);
    if (ntfs_inode_sync(ni) && r == 0) r = -1;
    ntfs_inode_close(ni);
    return r;
}

/* ---- fsck (ntfsfix-level) ---- */

/* Check via a real engine mount. Read-only mode verifies mountability and
 * reports the dirty flag; repair mode mounts with journal recovery (replays
 * $LogFile exactly like ntfsfix/Windows chkdsk's log pass) and clears the
 * dirty flag. Returns 0 clean, 1 was-dirty-now-fixed (repair) or dirty
 * (check-only), -1 unmountable/corrupt, -2 Windows is hibernated. */
int nk_fsck(const nk_io *io, int repair, char *errbuf, size_t errlen) {
    if (!io) return -1;
    struct nk_devctx *c = calloc(1, sizeof(*c));
    if (!c) return -1;
    c->io = *io;
    struct ntfs_device *dev = ntfs_device_alloc("fskit-fsck", 0, &nk_dev_ops, c);
    if (!dev) { free(c); return -1; }

    ntfs_mount_flags flags = repair ? NTFS_MNT_RECOVER : NTFS_MNT_RDONLY;
    ntfs_volume *vol = ntfs_device_mount(dev, flags);
    if (!vol) {
        int r = errno == EPERM ? -2 : -1;   /* EPERM = hibernated Windows */
        if (errbuf && errlen)
            snprintf(errbuf, errlen, "mount for fsck failed: %s", strerror(errno));
        ntfs_device_free(dev);
        free(c);
        return r;
    }
    int dirty = (vol->flags & VOLUME_IS_DIRTY) ? 1 : 0;
    int r = dirty;
    if (repair && dirty &&
        ntfs_volume_write_flags(vol, vol->flags & ~VOLUME_IS_DIRTY)) {
        if (errbuf && errlen)
            snprintf(errbuf, errlen, "could not clear dirty flag: %s",
                     strerror(errno));
        r = -1;
    }
    if (ntfs_umount(vol, FALSE) && r >= 0) {   /* frees dev */
        if (errbuf && errlen)
            snprintf(errbuf, errlen, "fsck unmount failed: %s", strerror(errno));
        r = -1;
    }
    free(c);
    return r;
}

/* ---- volume label ---- */

int nk_set_label(nk_volume *v, const char *label) {
    if (!v || !label) return -1;
    ntfschar *ucs = NULL;
    int len = ntfs_mbstoucs(label, &ucs);
    if (len < 0 || len > 128 || !ucs) { free(ucs); return -1; }
    int r = ntfs_volume_rename(v->vol, ucs, len);
    free(ucs);
    return r ? -1 : 0;
}

/* ---- extended attributes as NTFS named data streams (ADS) ----
 * macOS xattrs map 1:1 onto alternate data streams, so they round-trip to
 * Windows (visible as `file:name`) and back — no AppleDouble ._ files. */

static ntfschar *xattr_ucs(const char *name, int *out_len) {
    ntfschar *ucs = NULL;
    int len = ntfs_mbstoucs(name, &ucs);
    if (len <= 0 || len > 255 || !ucs) { free(ucs); return NULL; }
    *out_len = len;
    return ucs;
}

int nk_xattr_list(nk_volume *v, const char *path, nk_name_cb cb, void *ctx) {
    if (!v || !cb) return -1;
    ntfs_inode *ni = ntfs_pathname_to_inode(v->vol, NULL, path);
    if (!ni) return -1;
    int r = 0;
    ntfs_attr_search_ctx *sctx = ntfs_attr_get_search_ctx(ni, NULL);
    if (!sctx) { ntfs_inode_close(ni); return -1; }
    while (!ntfs_attr_lookup(AT_DATA, NULL, 0, CASE_SENSITIVE, 0, NULL, 0, sctx)) {
        if (!sctx->attr->name_length) continue;    /* unnamed = file data */
        char *utf8 = NULL;
        ntfschar *name = (ntfschar *)((u8 *)sctx->attr
                                      + le16_to_cpu(sctx->attr->name_offset));
        if (ntfs_ucstombs(name, sctx->attr->name_length, &utf8, 0) >= 0 && utf8) {
            if (cb(ctx, utf8)) { free(utf8); break; }
            free(utf8);
        }
    }
    ntfs_attr_put_search_ctx(sctx);
    ntfs_inode_close(ni);
    return r;
}

long long nk_xattr_get(nk_volume *v, const char *path, const char *name,
                       void *buf, long long bufsize) {
    if (!v || !name) return -1;
    int nlen = 0;
    ntfschar *ucs = xattr_ucs(name, &nlen);
    if (!ucs) return -1;
    ntfs_inode *ni = ntfs_pathname_to_inode(v->vol, NULL, path);
    if (!ni) { free(ucs); return -1; }
    long long r = -1;
    ntfs_attr *na = ntfs_attr_open(ni, AT_DATA, ucs, nlen);
    if (na) {
        if (!buf || bufsize == 0) {
            r = na->data_size;             /* size query */
        } else {
            r = ntfs_attr_pread(na, 0,
                                bufsize < na->data_size ? bufsize : na->data_size,
                                buf);
        }
        ntfs_attr_close(na);
    }
    ntfs_inode_close(ni);
    free(ucs);
    return r;
}

int nk_xattr_set(nk_volume *v, const char *path, const char *name,
                 const void *buf, long long size) {
    if (!v || !name || size < 0) return -1;
    int nlen = 0;
    ntfschar *ucs = xattr_ucs(name, &nlen);
    if (!ucs) return -1;
    ntfs_inode *ni = ntfs_pathname_to_inode(v->vol, NULL, path);
    if (!ni) { free(ucs); return -1; }
    int r = -1;
    ntfs_attr *na = ntfs_attr_open(ni, AT_DATA, ucs, nlen);
    if (na) {
        /* replace: overwrite FIRST, then shrink — a failed write leaves the
         * old (or mixed) value, never a zeroed stream */
        if ((size == 0 || ntfs_attr_pwrite(na, 0, size, buf) == size) &&
            !ntfs_attr_truncate(na, size))
            r = 0;
        ntfs_attr_close(na);
    } else if (!ntfs_attr_add(ni, AT_DATA, ucs, nlen,
                              (u8 *)(size ? buf : (const void *)""), size)) {
        r = 0;
    }
    ntfs_inode_mark_dirty(ni);
    ntfs_inode_close(ni);
    free(ucs);
    return r;
}

int nk_xattr_remove(nk_volume *v, const char *path, const char *name) {
    if (!v || !name) return -1;
    int nlen = 0;
    ntfschar *ucs = xattr_ucs(name, &nlen);
    if (!ucs) return -1;
    ntfs_inode *ni = ntfs_pathname_to_inode(v->vol, NULL, path);
    if (!ni) { free(ucs); return -1; }
    int r = -1;
    ntfs_attr *na = ntfs_attr_open(ni, AT_DATA, ucs, nlen);
    if (na) {
        r = ntfs_attr_rm(na) ? -1 : 0;     /* rm frees na on success */
        if (r != 0) ntfs_attr_close(na);
    }
    ntfs_inode_mark_dirty(ni);
    ntfs_inode_close(ni);
    free(ucs);
    return r;
}

/* ---- format (mkntfs) ---- */

extern int nk_mkntfs_main(int argc, char *argv[]);
extern struct ntfs_device *nk_mkntfs_external_dev;
extern int nk_mkntfs_dev_consumed;

/* Format the device behind `io` as NTFS with the given label, via the real
 * mkntfs (quick format). NOT thread-safe (mkntfs globals) and best called at
 * most once per process instance — fskitd spawns a fresh module process per
 * format task, which matches. Returns 0 / -1. */
int nk_format(const nk_io *io, const char *label, char *errbuf, size_t errlen) {
    if (!io) return -1;
    struct nk_devctx *c = calloc(1, sizeof(*c));
    if (!c) return -1;
    c->io = *io;
    struct ntfs_device *dev = ntfs_device_alloc("fskit-format", 0, &nk_dev_ops, c);
    if (!dev) { free(c); return -1; }

    /* getopt state is process-global — reset it or a second run fails. */
    optind = 1;
    optreset = 1;
    nk_mkntfs_external_dev = dev;
    nk_mkntfs_dev_consumed = 0;
    char *argv[] = { "mkntfs", "--force", "-F", "-Q",
                     "-L", (char *)(label && *label ? label : "NTFS"),
                     "fskit-format", NULL };
    int rc = nk_mkntfs_main(7, argv);
    nk_mkntfs_external_dev = NULL;
    /* mkntfs's cleanup frees the device only once it took ownership. */
    if (!nk_mkntfs_dev_consumed)
        ntfs_device_free(dev);
    free(c);
    if (rc != 0 && errbuf && errlen)
        snprintf(errbuf, errlen, "mkntfs failed (rc=%d)", rc);
    return rc == 0 ? 0 : -1;
}

const char *nk_engine_version(void) {
    return "libntfs-3g 2026.7.7 (native FSKit host, no FUSE)";
}
