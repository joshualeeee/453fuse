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

// Create a full path by pre-pending real_root to the path
static void fullpath(char fpath[PATH_MAX], const char *path);

/* Get the path to an IV file given the path to the original file
 * Stores the result in the provided iv_path buffer */
static void get_iv_path(char iv_path[PATH_MAX], const char *path);

// Create a corresponding file in the IV directory and puts an IV in it
static int create_iv_file(const char *path);

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

static void get_iv_path(char iv_path[PATH_MAX], const char *path)
{
    snprintf(iv_path, PATH_MAX, "%s/.iv%s", real_root, path);
}

static int create_iv_file(const char *path)
{
    // Create the file in the IV directory
    char iv_file[PATH_MAX];
    unsigned char iv_buffer[IV_SIZE_BYTES];
    get_iv_path(iv_file, path);

    /* Need to ensure that all directories in beween ./iv and the final file exist
     * Even though mkdir adds a corresponding directory to the ./iv dir, directories in the
     * original directory to mirror that existed prior to mounting won't have corresponding
     * entries in the ./iv dir and so need to be created on demand when an IV file is created
     * in one of those pre-existing directories
     */
    char *iv_dir_substring = iv_file + strlen(real_root);
    printf("iv_dir_loc_in_path: %s\n", iv_dir_substring);

    // continue until you reach the null byte (end of string)
    char *start = iv_dir_substring;
    char *end = start;
    while (*end)
    {
        while (*end && *end != '/')
        {
            end++;
        }

        if (*end)
        {
            *end = '\0'; // makes it so that iv_file contains directory ending at *end

            // 0755 = rwxr-xr-x
            if (mkdir(iv_file, 0755) == -1 && errno != EEXIST)
            {
                perror("mkdir");
                return -errno;
            }

            printf("Ensured directory exists or created directory at: %s\n", iv_file);

            *end = '/'; // restore character value
            start = end + 1;
            end = start;
        }
        else
        {
            // reached end of string before we reached a /, so break
            break;
        }
    }

    // create file in .iv dir
    int iv_fd = open(iv_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (iv_fd == -1)
    {
        perror("Failed to create IV file");
        return -errno; // Return error if IV file creation fails
    }

    // generate the random IV
    if (!generate_random_iv(iv_buffer))
    {
        return -EIO; // Generic error code return
    }

    // write the random IV to the file
    if (write(iv_fd, iv_buffer, IV_SIZE_BYTES) == -1)
    {
        perror("write");
        return -errno;
    }

    // Close the file
    if (close(iv_fd) == -1)
    {
        perror("close");
        return -errno;
    }

    // Success
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

    // Create the file in the IV directory
    int iv_res = create_iv_file(path);
    if (iv_res)
    {
        fprintf(stderr, "Failed to create an IV file in the /.iv directory!\n");
        return iv_res;
    }

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

    // mirror the directory in the IV directory
    char iv_dir[PATH_MAX];
    get_iv_path(iv_dir, path);
    mkdir(iv_dir, 0755);   // 0755 = rwxr-xr-x

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

    get_iv_path(ivfrom, from);
    get_iv_path(ivto, to);

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
    int fd;
    int res;
    int action;
    int iv_fd;
    char fpath[PATH_MAX];
    char iv_path[PATH_MAX];
    unsigned char iv_buffer[IV_SIZE_BYTES]; // Buffer for the IV
    FILE *tmp_file;
    fullpath(fpath, path);
    printf("original path: %s\n", path);
    printf("Writing to file: %s\n", fpath);

    // Open the file for writing or reading
    fd = open(fpath, O_RDWR);
    if (fd == -1)
        return -errno;

    // Use fdopen to get a FILE pointer for the file descriptor
    FILE *fp = fdopen(fd, "r+"); // "r+" for read/write, or "w" for write, etc.
    if (!fp)
    {
        perror("fdopen");
        close(fd);
        return -errno;
    }

    // if file is empty, return 0
    struct stat st;
    printf("Checking if file is empty...\n");
    if (fstat(fd, &st) == 0) {
        if (st.st_size == 0) {
            fclose(fp);
            return 0;
        }
    }



    // Check if a IV file exists for this file (if so, this file should be encrypted)
    get_iv_path(iv_path, path);
    if (access(iv_path, F_OK) == 0)
    {
        // IV file exists
        action = 1; // encrypt
        iv_fd = open(iv_path, O_RDONLY);

        // Open IV file and read IV into buffer
        if (iv_fd == -1)
        {
            perror("open");
            fclose(fp);
            return -errno;
        }

        if (read(iv_fd, iv_buffer, IV_SIZE_BYTES) == -1)
        {
            perror("read");
            close(iv_fd);
            fclose(fp);
            return -errno;
        }

        close(iv_fd);
    }
    else
    {
        // IV file does not exist
        action = -1; // pass-through
    }


            // Decrypt existing encrypted file into memory
            char temp_dec_path[] = "/tmp/tempDecryptedXXXXXX";
            int dec_fd = mkstemp(temp_dec_path);
            if (dec_fd == -1)
            {
                perror("mkstemp");
                fclose(fp);
                return -errno;
            }
            unlink(temp_dec_path); // ensure file is deleted after close

            FILE *dec_file = fdopen(dec_fd, "wb+");
            if (!dec_file)
            {
                perror("fdopen dec_file");
                close(dec_fd);
                fclose(fp);
                return -errno;
            }

            int decrypt_action = action == 1 ? 0 : -1;
            if (!do_crypt(fp, dec_file, decrypt_action, (char *)password, iv_buffer))
            {
                fprintf(stderr, "do_crypt failed (decrypt in append)\n");
                fclose(fp);
                fclose(dec_file);
                return -EIO;
            }

            // truncate the file to the new size
            fflush(dec_file);
            if (ftruncate(fileno(dec_file), size) != 0)
            {
                int err = errno;
                perror("ftruncate");
                fclose(fp);
                fclose(dec_file);
                return -err;
            }
            
            fstat(fileno(dec_file), &st);
            printf("After ftruncate, dec_file size: %ld\n", st.st_size);

            // Step 3: Re-encrypt updated content
            fflush(dec_file);
            rewind(dec_file);

            if (ftruncate(fd, 0) != 0)
            {
                int err = errno;
                perror("ftruncate");
                fclose(fp);
                fclose(dec_file);
                return -err;
            }

            rewind(fp);

            if (!do_crypt(dec_file, fp, action, (char *)password, iv_buffer))
            {
                fprintf(stderr, "do_crypt failed (re-encrypt)\n");
                fclose(fp);
                fclose(dec_file);
                return -EIO;
            }
            fflush(fp);
            fflush(dec_file);
            fclose(fp);
            fclose(dec_file);

            printf("File successfully appended and re-encrypted\n");
            res = size;

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
    int fd;
    char fpath[PATH_MAX];
    fullpath(fpath, path);
    (void)fi;

    // Open encrypted file
    fd = open(fpath, O_RDONLY);
    FILE *encrypted_file = fopen(fpath, "rb");
    if (!encrypted_file)
        return -errno;
    printf("successfully opened encrypted file!\n");

    char iv_path[PATH_MAX];
    unsigned char iv_buffer[IV_SIZE_BYTES];
    FILE *iv_file;

    // Get the path to the IV file
    get_iv_path(iv_path, path);
    printf("iv_path: %s\n", iv_path);

    // Check if the file is empty
    // if file is empty, return 0
    struct stat st;
    printf("Checking if file is empty...\n");
    if (fstat(fd, &st) == 0) {
        if (st.st_size == 0) {
            fclose(encrypted_file);
            return 0;
        }
    }

    // Check if IV file exists
    if (access(iv_path, F_OK) == 0)
    {
        // IV file exists: Open file and read IV into buffer
        printf("IV file exists: reading IV file\n");
        iv_file = fopen(iv_path, "rb");

        if (!iv_file)
        {
            fclose(encrypted_file);
            return -errno;
        }

        if (fread(iv_buffer, 1, IV_SIZE_BYTES, iv_file) != IV_SIZE_BYTES)
        {
            fclose(encrypted_file);
            fclose(iv_file);
            fprintf(stderr, "Error when getting iv!\n");
            return -EIO;
        }
        fclose(iv_file);
        printf("Successfully read IV file\n");
    }
    else
    {
        // IV file does not exist: read file without decrypting
        printf("IV file does not exist: reading file without decryption\n");
        if (fseeko(encrypted_file, offset, SEEK_SET) != 0)
        {
            fclose(encrypted_file);
            return -errno;
        }

        // Read file into buffer (no decryption)
        int res = fread(buf, 1, size, encrypted_file);
        if (res != size && ferror(encrypted_file))
        {
            int err = errno;
            fclose(encrypted_file);
            return -err;
        }

        // Return number of bytes read
        return res;
    }

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
    // good practice to unlink immediately after creating temp file (since it's open, won't be deleted yet)
    unlink(temp_path);

    // Decrypt
    if (!do_crypt(encrypted_file, dec_file, 0, password, iv_buffer))
    {
        fclose(encrypted_file);
        fclose(dec_file);
        fprintf(stderr, "do_crypt error\n");
        return -EIO;
    }
    fclose(encrypted_file);

    // Read from decrypted file
    if (fseeko(dec_file, offset, SEEK_SET) != 0)
    {
        fclose(dec_file);
        return -errno;
    }

    int res = fread(buf, 1, size, dec_file);
    if (res != size && ferror(dec_file))
    {
        int err = errno;
        fclose(dec_file);
        return -err;
    }

    fclose(dec_file);
    return res;
}

// If write is called then the file needs to be decrypted before writing
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
    int action;
    int iv_fd;
    char fpath[PATH_MAX];
    char iv_path[PATH_MAX];
    unsigned char iv_buffer[IV_SIZE_BYTES]; // Buffer for the IV
    FILE *tmp_file;
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
    if (!fp)
    {
        perror("fdopen");
        close(fd);
        return -errno;
    }

    // Temporary file to store encrypted output
    char temp_path[] = "/tmp/tempEncryptedXXXXXX";
    printf("Encryption output path: %s\n", temp_path);

    // make temp file for encryption
    int tmp_fd = mkstemp(temp_path);
    if (tmp_fd == -1)
    {
        fclose(fp);
        return -errno;
    }
    // good practice to unlink temp files; since it's open now, it won't be deleted yet
    unlink(temp_path);

    // Check if a IV file exists for this file (if so, this file should be encrypted)
    get_iv_path(iv_path, path);
    if (access(iv_path, F_OK) == 0)
    {
        // IV file exists
        action = 1; // encrypt
        iv_fd = open(iv_path, O_RDONLY);

        // Open IV file and read IV into buffer
        if (iv_fd == -1)
        {
            perror("open");
            fclose(fp);
            close(tmp_fd);
            return -errno;
        }

        if (read(iv_fd, iv_buffer, IV_SIZE_BYTES) == -1)
        {
            perror("read");
            close(iv_fd);
            fclose(fp);
            close(tmp_fd);
            return -errno;
        }

        close(iv_fd);
    }
    else
    {
        // IV file does not exist
        action = -1; // pass-through
    }

    struct stat st;
    // Check if the file is empty before writing
    if (fstat(fd, &st) == 0)
    {
        if (st.st_size == 0)
        {
            printf("File is empty, writing directly and encrypting\n");

            // if the file is empty, write the buffer directly to temporary file
            res = pwrite(tmp_fd, buf, size, offset);
            if (res == -1)
                res = -errno;

            // Reset the file pointer to the beginning
            if (lseek(tmp_fd, 0, SEEK_SET) == -1)
            {
                fclose(fp);
                close(tmp_fd);
                return -errno;
            }

            tmp_file = fdopen(tmp_fd, "wb+");
            if (!tmp_file)
            {
                perror("fdopen");
                close(tmp_fd);
                fclose(fp);
                return -errno;
            }

            // Encrypt from temporary file to actual file
            if (!do_crypt(tmp_file, fp, action, (char *)password, iv_buffer))
            {
                fclose(fp);
                fclose(tmp_file);
                return -EIO;
            }
            printf("Encryption successful, writing to output file\n");
            fclose(fp);
            fclose(tmp_file);

            printf("File encrypted and saved successfully.\n");
        }

        else
        {
            // append

            // Decrypt existing encrypted file into memory
            char temp_dec_path[] = "/tmp/tempDecryptedXXXXXX";
            int dec_fd = mkstemp(temp_dec_path);
            if (dec_fd == -1)
            {
                perror("mkstemp");
                fclose(fp);
                close(tmp_fd);
                return -errno;
            }
            unlink(temp_dec_path); // ensure file is deleted after close

            FILE *dec_file = fdopen(dec_fd, "wb+");
            if (!dec_file)
            {
                perror("fdopen dec_file");
                close(dec_fd);
                fclose(fp);
                return -errno;
            }

            int decrypt_action = action == 1 ? 0 : -1;
            if (!do_crypt(fp, dec_file, decrypt_action, (char *)password, iv_buffer))
            {
                fprintf(stderr, "do_crypt failed (decrypt in append)\n");
                fclose(fp);
                fclose(dec_file);
                return -EIO;
            }

            // Append new content
            if (fseeko(dec_file, offset, SEEK_SET) != 0)
            {
                int err = errno;
                perror("fseeko (append)");
                fclose(fp);
                fclose(dec_file);
                return -err;
            }

            if (fwrite(buf, 1, size, dec_file) != size)
            {
                int err = errno;
                perror("fwrite (append)");
                fclose(fp);
                fclose(dec_file);
                return -err;
            }

            // Step 3: Re-encrypt updated content
            rewind(dec_file);

            if (ftruncate(fd, 0) != 0)
            {
                int err = errno;
                perror("ftruncate");
                fclose(fp);
                fclose(dec_file);
                return -err;
            }

            rewind(fp);

            if (!do_crypt(dec_file, fp, action, (char *)password, iv_buffer))
            {
                fprintf(stderr, "do_crypt failed (re-encrypt)\n");
                fclose(fp);
                fclose(dec_file);
                return -EIO;
            }

            fclose(fp);
            fclose(dec_file);

            printf("File successfully appended and re-encrypted\n");
            res = size;
        }
    } else {
        res = -errno;
    }

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
    int fuse_res = fuse_main(argc, argv, &xmp_oper, NULL);
    free(real_root); // realpath() allocates memory for real_root, so should free it
    return fuse_res;
}
