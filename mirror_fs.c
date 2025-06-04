/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001-2006  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.

    gcc -Wall `pkg-config fuse --cflags --libs` fusexmp.c -o fusexmp
*/

#define FUSE_USE_VERSION 26

// #include <config.h>

#ifdef linux
/* For pread()/pwrite() */
#define _XOPEN_SOURCE 500
#endif

#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h> // for PATH_MAX
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>

#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#include "aes-crypt.h"

// Global variables
static char *real_root;
static char password[256]; // Buffer for the password input// Global variable to hold the password input

static void fullpath(char fpath[PATH_MAX], const char *path);

static int xmp_getattr(const char *path, struct stat *stbuf)
{
    int res;
    char fpath[PATH_MAX];
    fullpath(fpath, path);
    res = lstat(fpath, stbuf);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_access(const char *path, int mask)
{
    int res;
    char fpath[PATH_MAX];
    fullpath(fpath, path);
    res = access(fpath, mask);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_readlink(const char *path, char *buf, size_t size)
{
    int res;
    char fpath[PATH_MAX];
    fullpath(fpath, path);
    res = readlink(fpath, buf, size - 1);
    if (res == -1)
        return -errno;

    buf[res] = '\0';
    return 0;
}

static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                       off_t offset, struct fuse_file_info *fi)
{
    DIR *dp;
    struct dirent *de;
    char fpath[PATH_MAX];

    (void)offset;
    (void)fi;

    fullpath(fpath, path);
    dp = opendir(fpath);
    if (dp == NULL)
        return -errno;

    while ((de = readdir(dp)) != NULL)
    {
        struct stat st;
        memset(&st, 0, sizeof(st));
        st.st_ino = de->d_ino;
        st.st_mode = de->d_type << 12;
        if (filler(buf, de->d_name, &st, 0))
            break;
    }

    closedir(dp);
    return 0;
}

// Create a file or a special file (FIFO, device, etc.)a
// create iv file here instead of in write
static int xmp_mknod(const char *path, mode_t mode, dev_t rdev)
{
    int res;
    char fpath[PATH_MAX];
    fullpath(fpath, path);

    /* On Linux this could just be 'mknod(path, mode, rdev)' but this
       is more portable */
    if (S_ISREG(mode))
    {
        res = open(fpath, O_CREAT | O_EXCL | O_WRONLY, mode);
        if (res >= 0)
            res = close(res);
    }
    else if (S_ISFIFO(mode))
        res = mkfifo(fpath, mode);
    else
        res = mknod(fpath, mode, rdev);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_mkdir(const char *path, mode_t mode)
{
    int res;
    char fpath[PATH_MAX];
    fullpath(fpath, path);

    res = mkdir(fpath, mode);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_unlink(const char *path)
{
    int res;
    char fpath[PATH_MAX];
    fullpath(fpath, path);

    res = unlink(fpath);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_rmdir(const char *path)
{
    int res;
    char fpath[PATH_MAX];
    fullpath(fpath, path);

    res = rmdir(fpath);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_symlink(const char *from, const char *to)
{
    int res;
    char fpath[PATH_MAX];
    fullpath(fpath, to);

    res = symlink(from, fpath);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_rename(const char *from, const char *to)
{
    int res;
    char ffrom[PATH_MAX];
    char fto[PATH_MAX];

    fullpath(ffrom, from);
    fullpath(fto, to);

    res = rename(ffrom, fto);
    if (res == -1)
        return -errno;

    char ivfrom[PATH_MAX];
    char ivto[PATH_MAX];

    snprintf(ivfrom, PATH_MAX, "%s/.iv%s.iv", real_root, from);
    snprintf(ivto, PATH_MAX, "%s/.iv%s.iv", real_root, to);

    // Attempt to rename the IV file; it's okay if it doesn't exist
    if (rename(ivfrom, ivto) == -1 && errno != ENOENT)
        return -errno;

    return 0;
}

static int xmp_link(const char *from, const char *to)
{
    int res;
    char ffrom[PATH_MAX];
    char fto[PATH_MAX];

    fullpath(ffrom, from);
    fullpath(fto, to);

    res = link(ffrom, fto);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_chmod(const char *path, mode_t mode)
{
    int res;
    char fpath[PATH_MAX];
    fullpath(fpath, path);

    res = chmod(fpath, mode);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_chown(const char *path, uid_t uid, gid_t gid)
{
    int res;
    char fpath[PATH_MAX];
    fullpath(fpath, path);

    res = lchown(fpath, uid, gid);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_truncate(const char *path, off_t size)
{
    int res;
    char fpath[PATH_MAX];
    fullpath(fpath, path);

    res = truncate(fpath, size);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_utimens(const char *path, const struct timespec ts[2])
{
    int res;
    struct timeval tv[2];
    char fpath[PATH_MAX];
    fullpath(fpath, path);

    tv[0].tv_sec = ts[0].tv_sec;
    tv[0].tv_usec = ts[0].tv_nsec / 1000;
    tv[1].tv_sec = ts[1].tv_sec;
    tv[1].tv_usec = ts[1].tv_nsec / 1000;

    res = utimes(fpath, tv);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_open(const char *path, struct fuse_file_info *fi)
{
    int res;
    char fpath[PATH_MAX];
    fullpath(fpath, path);

    res = open(fpath, fi->flags);
    if (res == -1)
        return -errno;

    close(res);
    return 0;
}

static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
                    struct fuse_file_info *fi)
{

    printf("xmp_read called for path: %s\n", path);

    char fpath[PATH_MAX];
    fullpath(fpath, path);
    (void)fi;

    // Open encrypted file
    FILE *encrypted_file = fopen(fpath, "rb");
    if (!encrypted_file)
        return -errno;

    char iv_path[PATH_MAX];
    snprintf(iv_path, PATH_MAX, "%s/.iv%s.iv", real_root, path);

    // Open iv file
    FILE *iv_file = fopen(iv_path, "rb");
    if (!iv_file)
    {
        fclose(encrypted_file);
        return -errno;
    }

    // Grab the IV
    unsigned char iv_buffer[IV_SIZE_BYTES];
    if (fread(iv_buffer, 1, IV_SIZE_BYTES, iv_file) != IV_SIZE_BYTES)
    {
        fclose(encrypted_file);
        fclose(iv_file);
        printf("getting iv error\n");
        return -EIO;
    }
    fclose(iv_file);

    // Temporary file to store decrypted output
    char temp_path[] = "/tmp/tempDecryptedXXXXXX";
    printf("Decryption output path: %s\n", temp_path);

    // make temp file for decryption
    int tmp_fd = mkstemp(temp_path);
    if (tmp_fd == -1)
    {
        fclose(encrypted_file);
        return -errno;
    }
    FILE *dec_file = fdopen(tmp_fd, "wb+");

    // Decrypt
    if (!do_crypt(encrypted_file, dec_file, 0, password, iv_buffer))
    {
        fclose(encrypted_file);
        fclose(dec_file);
        unlink(temp_path);
        printf("do_crypt error\n");
        return -EIO;
    }
    fclose(encrypted_file);

    // Read from decrypted file
    if (fseeko(dec_file, offset, SEEK_SET) != 0)
    {
        fclose(dec_file);
        unlink(temp_path);
        return -errno;
    }

    int res = fread(buf, 1, size, dec_file);
    if (res < 0)
    {
        fclose(dec_file);
        unlink(temp_path);
        return -errno;
    }

    fclose(dec_file);
    unlink(temp_path);
    return res;
}

// If write is called then the file needs to be decrypeted before writing
// Then the entire file is encrypted again after writing
// Removes everything after the first '.' in the filename (modifies in place)
void remove_after_dot(char *filename)
{
    char *dot = strchr(filename, '.');
    if (dot)
    {
        *dot = '\0';
    }
}

static int xmp_write(const char *path, const char *buf, size_t size,
                     off_t offset, struct fuse_file_info *fi)
{
    int fd;
    int res;
    char fpath[PATH_MAX];
    unsigned char iv_buffer[IV_SIZE_BYTES]; // Buffer for the IV
    fullpath(fpath, path);
    printf("original path: %s\n", path);
    printf("Writing to file: %s\n", fpath);

    (void)fi;
    // Open the file for writing or reading
    fd = open(fpath, O_RDWR);
    if (fd == -1)
        return -errno;

    // Use fdopen to get a FILE pointer for the file descriptor
    FILE *fp = fdopen(fd, "r+"); // "r+" for read/write, or "w" for write, etc.
    char outpath[PATH_MAX];
    fullpath(outpath, "/encrypted_file.txt"); // Temporary file for encrypted output
    printf("Output path: %s\n", outpath);
    FILE *out = fopen(outpath, "wb");

    if (!fp)
    {
        // handle error
    }

    char iv_path[PATH_MAX];
    snprintf(iv_path, PATH_MAX, "%s/.iv/", real_root); // create .iv directory
    printf("IV path: %s\n", iv_path);

    // Create the .iv directory if it doesn't exist
    if (mkdir(iv_path, 0755) == -1 && errno != EEXIST)
    {
        perror("Failed to create .iv directory");
        return -errno; // Return error if directory creation fails
    }

    struct stat st;
    // Check if the file is empty before writing
    if (fstat(fd, &st) == 0)
    {
        if (st.st_size == 0)
        {
            printf("File is empty, writing directly and encrypting\n");

            // if the file is empty, write the buffer directly then encrypt it
            res = pwrite(fd, buf, size, offset);
            if (res == -1)
                res = -errno;

            // Encrypt the file after writing
            // Reset the file pointer to the beginning
            if (lseek(fd, 0, SEEK_SET) == -1)
            {
                close(fd);
                fclose(out);
                return -errno;
            }

            // Encrypt to temporary file
            if (!do_crypt(fp, out, 1, (char *)password, iv_buffer))
            {
                close(fd);
                fclose(out);
                return -EIO;
            }
            printf("Encryption successful, writing to output file\n");
            fclose(out);
            close(fd);

            // Overwrite the original file with the encrypted file
            if (rename(outpath, fpath) == -1)
            {
                return -errno;
            }

            // Create the IV file
            char iv_file[PATH_MAX];

            // Create the IV file path
            snprintf(iv_file, PATH_MAX, "%s/.iv%s.iv", real_root, path);
            printf("IV file path: %s\n", iv_file);

            // Debug: Print the IV in hex format
            // printf("IV used for encryption/decryption: ");
            // int i =0;
            // for (i = 0; i < IV_SIZE_BYTES; i++) {
            //     printf("%02x", iv_buffer[i]);
            // }

            // Open the IV file for writing, creating it if it doesn't exist
            int iv_fd = open(iv_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);

            if (iv_fd == -1)
            {
                perror("Failed to create IV file");
                return -errno; // Return error if IV file creation fails
            }

            // Write the IV to the file
            int iv_bytes_written = 0;
            iv_bytes_written = pwrite(iv_fd, iv_buffer, IV_SIZE_BYTES, 0);

            // Check if writing the IV was successful
            if (iv_bytes_written == -1)
            {
                close(iv_fd);
                perror("Failed to write IV to file");
                return -EIO; // Return error if writing IV fails
            }

            close(iv_fd);

            printf("File encrypted and IV saved successfully.\n");
        }

        else
        {
            // NEED to implement append

            res = pwrite(fd, buf, size, offset);
            if (res == -1)
                res = -errno;
        }
    }

    close(fd);
    return res;
}

static int xmp_statfs(const char *path, struct statvfs *stbuf)
{
    int res;
    char fpath[PATH_MAX];
    fullpath(fpath, path);

    res = statvfs(fpath, stbuf);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_release(const char *path, struct fuse_file_info *fi)
{
    /* Just a stub.  This method is optional and can safely be left
       unimplemented */
    char fpath[PATH_MAX];
    fullpath(fpath, path);

    (void)fpath;
    (void)fi;
    return 0;
}

static int xmp_fsync(const char *path, int isdatasync,
                     struct fuse_file_info *fi)
{
    /* Just a stub.  This method is optional and can safely be left
       unimplemented */
    char fpath[PATH_MAX];
    fullpath(fpath, path);
    (void)fpath;
    (void)isdatasync;
    (void)fi;
    return 0;
}

#ifdef HAVE_SETXATTR
/* xattr operations are optional and can safely be left unimplemented */
static int xmp_setxattr(const char *path, const char *name, const char *value,
                        size_t size, int flags)
{
    char fpath[PATH_MAX];
    fullpath(fpath, path);
    int res = lsetxattr(fpath, name, value, size, flags);
    if (res == -1)
        return -errno;
    return 0;
}

static int xmp_getxattr(const char *path, const char *name, char *value,
                        size_t size)
{
    char fpath[PATH_MAX];
    fullpath(fpath, path);
    int res = lgetxattr(fpath, name, value, size);
    if (res == -1)
        return -errno;
    return res;
}

static int xmp_listxattr(const char *path, char *list, size_t size)
{
    char fpath[PATH_MAX];
    fullpath(fpath, path);
    int res = llistxattr(fpath, list, size);
    if (res == -1)
        return -errno;
    return res;
}

static int xmp_removexattr(const char *path, const char *name)
{
    char fpath[PATH_MAX];
    fullpath(fpath, path);
    int res = lremovexattr(fpath, name);
    if (res == -1)
        return -errno;
    return 0;
}
#endif /* HAVE_SETXATTR */

static struct fuse_operations xmp_oper = {
    .getattr = xmp_getattr,
    .access = xmp_access,
    .readlink = xmp_readlink,
    .readdir = xmp_readdir,
    .mknod = xmp_mknod,
    .mkdir = xmp_mkdir,
    .symlink = xmp_symlink,
    .unlink = xmp_unlink,
    .rmdir = xmp_rmdir,
    .rename = xmp_rename,
    .link = xmp_link,
    .chmod = xmp_chmod,
    .chown = xmp_chown,
    .truncate = xmp_truncate,
    .utimens = xmp_utimens,
    .open = xmp_open,
    .read = xmp_read,
    .write = xmp_write,
    .statfs = xmp_statfs,
    .release = xmp_release,
    .fsync = xmp_fsync,
#ifdef HAVE_SETXATTR
    .setxattr = xmp_setxattr,
    .getxattr = xmp_getxattr,
    .listxattr = xmp_listxattr,
    .removexattr = xmp_removexattr,
#endif
};

// // password: user input (null-terminated string)
// // key: output buffer (must be at least 32 bytes)
// void derive_key(const char *password, unsigned char key[32]) {
//     SHA256((const unsigned char *)password, strlen(password), key);
// }

static void fullpath(char fpath[PATH_MAX], const char *path)
{
    snprintf(fpath, PATH_MAX, "%s%s", real_root, path);
}

int main(int argc, char *argv[])
{
    if (argc < 3)
    {
        fprintf(stderr, "Usage: %s [FUSE options] <mountpoint> <mirror_dir>\n", argv[0]);
        exit(1);
    }

    // Mirror dir is always the last argument
    const char *mirror_dir = argv[argc - 1];

    // Resolve real path to be prepended to every dir operation
    real_root = realpath(mirror_dir, NULL);
    if (!real_root)
    {
        perror("realpath");
        exit(1);
    }

    // Remove mirror_dir from argv, keep FUSE args and mountpoint intact
    argc--; // drop the mirror_dir argument

    // Get password input from the user and then derive the key

    printf("Enter password for decryption: ");
    fgets(password, sizeof(password), stdin);
    password[strcspn(password, "\n")] = 0; // Remove newline character

    printf("password: %s\n", password);

    umask(0);
    return fuse_main(argc, argv, &xmp_oper, NULL);
}
