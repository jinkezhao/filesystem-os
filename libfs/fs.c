#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "disk.h"
#include "fs.h"

/* DEFINITIONS */
#define FAT_EOC 0xFFFF
#define BLOCK_SIZE 4096
#define SIGNATURE "ECS150FS"
#define SUCCESS 0
#define FAILURE -1
#define MAX_FILE_NAME 16


/**
 * struct for the super block
 */
struct __attribute__((__packed__)) superblock_struct {
    char signature[8];
    uint16_t total_blocks_count;
    uint16_t root_directory_block_index;
    uint16_t data_block_start_index;
    uint16_t amount_data_block;
    uint8_t number_of_blocks_for_FAT;
    char padding[4079];
};

/* ROOT DIRECTORY */
struct __attribute__((__packed__)) directory_entry_struct {
    char file_name[MAX_FILE_NAME];
    uint32_t file_size;
    uint16_t data_index;
    char padding[10];
};

/* directory_entry_struct DESCRIPTOR */
struct open_file_pointer {
    struct directory_entry_struct *file;
    int offset;
    int allocated;
};

/* DECLARING VARIABLES */
struct superblock_struct *super_block;
uint16_t *fat;
struct directory_entry_struct *root_directory;

// Open Files
struct open_file_pointer fd_table[FS_OPEN_MAX_COUNT];
int open_file_count = 0;

/* HELPER FUNCTIONS */

/**
 * if FS is mounted, return 1, else return 0
 */
int is_mounted();

/*
 * if the super block is consistent, return 1, else return 0
 */
int check_consistency();

/*
 * if the file name is not null or len is not exceeding the max len return 1, else return 0
 */
int is_valid_file_name(const char *file_name);

/*
 * if the root directory is full or there is already a file with the same name, return 1, else return 0
 */
int is_root_full_or_duplicate(const char *file_name);

/*
 * count the number of free data blocks
 */
int get_num_free_block();

/*
 * count the number of free entry in the root directory
 */
int get_num_free_entry();

/*
 * check if a file exists in the root directory
 */

int is_exist(const char *file_name);

/*
 * check if a file is opened now
 */

int is_open(const char *file_name);

/*
 * given file name, find its index in root directory
 */

int get_root_directory_index(const char *file_name);


/*
 * get the index of the data block corresponding to the file's offset
 */

uint16_t get_data_block_index(int fd);

/*
 * get_next_free_block
 *
 * Description: Extracts the next free block from the fat table.
 */
int find_next_free_block();



/**
 * fs_mount - Mount a file system
 * @diskname: Name of the virtual disk file
 *
 * Open the virtual disk file @diskname and mount the file system that it
 * contains. A file system needs to be mounted before files can be read from it
 * with fs_read() or written to it with fs_write().
 *
 * Return: -1 if virtual disk file @diskname cannot be opened, or if no valid
 * file system can be located. 0 otherwise.
 */
int fs_mount(const char *diskname) {
//    printf("fs_mount start\n");
    //try to load the dick, -1 indicate failure to open the disk file
    if (block_disk_open(diskname) == -1) {
        return FAILURE;
    }

    // allocate space for the super block, return -1 if failed
    if ((super_block = (struct superblock_struct *) malloc(sizeof(struct superblock_struct))) == NULL) {
        return FAILURE;
    }

    // Read into super_block
    block_read(0, super_block);

    if (check_consistency() == FAILURE) {
        printf("super block does not pass consistency check\n");
        return FAILURE;
    }

    root_directory = (struct directory_entry_struct *) malloc(sizeof(struct directory_entry_struct) * FS_FILE_MAX_COUNT);
    block_read(super_block->root_directory_block_index, root_directory);

    // Initialize @data_blk and @file_table (FAT)
    uint16_t *data_blk = malloc(sizeof(uint16_t) * BLOCK_SIZE);
    fat = malloc(sizeof(uint16_t) * super_block->number_of_blocks_for_FAT * BLOCK_SIZE);

    // @index - Add with @i in order to get correct index for FAT
    int index = 0;
    for (int i = 1; i <= super_block->number_of_blocks_for_FAT; i++) {
        // Read each data block, and copy it into @fat, also increment index
        block_read(i, data_blk);
        memcpy(fat + index, data_blk, BLOCK_SIZE);
        index += 4096;
    }

    for (int i = 0; i < FS_OPEN_MAX_COUNT; ++i) {
        fd_table[i].allocated = 0;
    }
    open_file_count = 0;

//    printf("fs_mount successful\n");
    // Success
    return SUCCESS;
}

/**
 * fs_umount - Unmount file system
 *
 * Unmount the currently mounted file system and close the underlying virtual
 * disk file.
 *
 * Return: -1 if no FS is currently mounted, or if the virtual disk cannot be
 * closed, or if there are still open file descriptors. 0 otherwise.
 */
int fs_umount(void) {
    /**
     * if there is no disk mounted
     */
    if (!is_mounted()) {
        return FAILURE;
    }

    /**
     * if there are still open file descriptors
     */
    if (open_file_count > 0) {
        return FAILURE;
    }

    // All data must be  written to the vritual disk
    block_write(0, super_block);
    block_write(1, fat);
    block_write(super_block->root_directory_block_index, root_directory);
//    block_write(2, fat + BLOCK_SIZE);

    // try to close the dick
    if (block_disk_close() == -1) {
        return FAILURE;
    }

    // release memory
    free(super_block);
    free(fat);
    free(root_directory);

    return SUCCESS;
}

/**
 * fs_info - Display information about file system
 *
 * Display some information about the currently mounted file system.
 *
 * Return: -1 if no underlying virtual disk was opened. 0 otherwise.
 */
int fs_info(void) {
    /*
     * check if any file system mounted
     */
    if (!is_mounted()) {
        return FAILURE;
    }

    printf("FS Info:\n");
    printf("total_blk_count=%d\n", super_block->total_blocks_count);
    printf("fat_blk_count=%d\n", super_block->number_of_blocks_for_FAT);
    printf("rdir_blk=%d\n", super_block->root_directory_block_index);
    printf("data_blk=%d\n", super_block->data_block_start_index);
    printf("data_blk_count=%d\n", super_block->amount_data_block);
    printf("fat_free_ratio=%d/%d\n", get_num_free_block(), super_block->amount_data_block);
    printf("rdir_free_ratio=%d/%d\n", get_num_free_entry(), FS_FILE_MAX_COUNT);

    return SUCCESS;
}


/**
 * fs_create - Create a new file
 * @filename: File name
 *
 * Create a new and empty file named @filename in the root directory of the
 * mounted file system. String @filename must be NULL-terminated and its total
 * length cannot exceed %FS_FILENAME_LEN characters (including the NULL
 * character).
 *
 * Return: -1 if no FS is currently mounted, or if @filename is invalid, or if a
 * file named @filename already exists, or if string @filename is too long, or
 * if the root directory already contains %FS_FILE_MAX_COUNT files. 0 otherwise.
 */
int fs_create(const char *filename) {
    /*
     * if no FS is mounted or filename is not valid or the root directory is full or there is
     * already a file with the name
     */
    if (!is_mounted() || !is_valid_file_name(filename) || is_root_full_or_duplicate(filename)) {
        return FAILURE;
    }

    /*
     * after passing the above check, there must be a free entry for the new file
     */
    int i;
    for (i = 0; i < FS_FILE_MAX_COUNT; i++) {
        /*
         * free entry
         */
        if ((root_directory[i].file_name[0] == '\0')) {
            break;
        }
    }


    /*
     * set the content of the entry
     */
    strcpy(root_directory[i].file_name, filename);
    root_directory[i].file_size = 0;
    root_directory[i].data_index = FAT_EOC;

    return SUCCESS;
}


/**
 * fs_delete - Delete a file
 * @filename: File name
 *
 * Delete the file named @filename from the root directory of the mounted file
 * system.
 *
 * Return: -1 if no FS is currently mounted, or if @filename is invalid, or if
 * Return: -1 if @filename is invalid, if there is no file named @filename to
 * delete, or if file @filename is currently open. 0 otherwise.
 */
int fs_delete(const char *filename) {

    // Check if filename is valid
    if (strnlen(filename, FS_FILENAME_LEN) >= FS_FILENAME_LEN) {
        return -1;
    }

    /*
     * if no FS is mounted or filename is not valid or file does not exist or if the file is opened
     */
    if (!is_mounted() || !is_valid_file_name(filename) || !is_exist(filename) || is_open(filename)) {
        return FAILURE;
    }


    int i = get_root_directory_index(filename);
    /*
     * after passing the above check, it is impossible for i == -1, because the file name exists in the
     * root directory
     */
    if (i == -1) {
        printf("Impossible\n");
        exit(EXIT_FAILURE);
    }

    root_directory[i].file_name[0] = '\0';
    uint16_t current_FAT_index = root_directory[i].data_index;
    uint16_t temp_index;
    while (current_FAT_index != FAT_EOC) {
        temp_index = fat[current_FAT_index];
        fat[current_FAT_index] = 0;
        current_FAT_index = temp_index;
    }

    return SUCCESS;
}


/**
 * fs_ls - List files on file system
 *
 * List information about the files located in the root directory.
 *
 * Return: -1 if no FS is currently mounted. 0 otherwise.
 */
int fs_ls(void) {
    if (!is_mounted()) {
        return FAILURE;
    }

    printf("FS Ls:\n");
    int i = 0;
    while (i < FS_FILE_MAX_COUNT) {
        if (root_directory[i].file_name[0] != '\0') {
            printf("file: %s, size: %d, data_blk: %d\n",
                   root_directory[i].file_name,
                   root_directory[i].file_size,
                   root_directory[i].data_index);
        }
        ++i;
    }

    return SUCCESS;
}


/**
 * fs_open - Open a file
 * @filename: File name
 *
 * Open file named @filename for reading and writing, and return the
 * corresponding file descriptor. The file descriptor is a non-negative integer
 * that is used subsequently to access the contents of the file. The file offset
 * of the file descriptor is set to 0 initially (beginning of the file). If the
 * same file is opened multiple files, fs_open() must return distinct file
 * descriptors. A maximum of %FS_OPEN_MAX_COUNT files can be open
 * simultaneously.
 *
 * Return: -1 if no FS is currently mounted, or if @filename is invalid, or if
 * there is no file named @filename to open, or if there are already
 * %FS_OPEN_MAX_COUNT files currently open. Otherwise, return the file
 * descriptor.
 */
int fs_open(const char *filename) {

    if (!is_mounted() || !is_valid_file_name(filename) || !is_exist(filename) || open_file_count == FS_OPEN_MAX_COUNT) {
        return FAILURE;
    }

    int root_directory_index = get_root_directory_index(filename);
    /*
     * after passing the above check, it is impossible for i == -1, because the file name exists in the
     * root directory
     */
    if (root_directory_index == -1) {
        printf("Impossible\n");
        exit(EXIT_FAILURE);
    }

    for (int fd_index = 0; fd_index < FS_OPEN_MAX_COUNT; ++fd_index) {
        if (!fd_table[fd_index].allocated) {
            fd_table[fd_index].file = &(root_directory[root_directory_index]);
            fd_table[fd_index].offset = 0;
            fd_table[fd_index].allocated = 1;
            ++open_file_count;
            return fd_index;
        }
    }

    /*
     * this should be unreachable since it is checked that FS_OPEN_MAX_COUNT is not reached
     */
    return FAILURE;
}

/**
 * fs_close - Close a file
 * @fd: File descriptor
 *
 * Close file descriptor @fd.
 *
 * Return: -1 if no FS is currently mounted, or if file descriptor @fd is
 * invalid (out of bounds or not currently open). 0 otherwise.
 */
int fs_close(int fd) {

    if (!is_mounted() || fd < 0 || fd >= FS_OPEN_MAX_COUNT || !fd_table[fd].allocated) {
        return FAILURE;
    }

    fd_table[fd].allocated = 0;
    --open_file_count;

    return SUCCESS;
}

/**
 * fs_stat - Get file status
 * @fd: File descriptor
 *
 * Get the current size of the file pointed by file descriptor @fd.
 *
 * Return: -1 if no FS is currently mounted, of if file descriptor @fd is
 * invalid (out of bounds or not currently open). Otherwise return the current
 * size of file.
 */
int fs_stat(int fd) {

    if (!is_mounted() || fd < 0 || fd >= FS_OPEN_MAX_COUNT || !fd_table[fd].allocated) {
        return FAILURE;
    }

    return fd_table[fd].file->file_size;

}


/**
 * fs_lseek - Set file offset
 * @fd: File descriptor
 * @offset: File offset
 *
 * Set the file offset (used for read and write operations) associated with file
 * descriptor @fd to the argument @offset. To append to a file, one can call
 * fs_lseek(fd, fs_stat(fd));
 *
 * Return: -1 if no FS is currently mounted, or if file descriptor @fd is
 * invalid (i.e., out of bounds, or not currently open), or if @offset is larger
 * than the current file size. 0 otherwise.
 */
int fs_lseek(int fd, size_t offset) {
    // TODO: OFFSET BOUND

    if (!is_mounted() || fd < 0 || fd >= FS_OPEN_MAX_COUNT || !fd_table[fd].allocated ||
        offset > fd_table[fd].file->file_size) {
        return FAILURE;
    }
    fd_table[fd].offset = offset;
    return SUCCESS;
}


/**
 * fs_write - Write to a file
 * @fd: File descriptor
 * @buf: Data buffer to write in the file
 * @count: Number of bytes of data to be written
 *
 * Attempt to write @count bytes of data from buffer pointer by @buf into the
 * file referenced by file descriptor @fd. It is assumed that @buf holds at
 * least @count bytes.
 *
 * When the function attempts to write past the end of the file, the file is
 * automatically extended to hold the additional bytes. If the underlying disk
 * runs out of space while performing a write operation, fs_write() should write
 * as many bytes as possible. The number of written bytes can therefore be
 * smaller than @count (it can even be 0 if there is no more space on disk).
 *
 * Return: -1 if no FS is currently mounted, or if file descriptor @fd is
 * invalid (out of bounds or not currently open), or if @buf is NULL. Otherwise
 * return the number of bytes actually written.
 */
int fs_write(int fd, void *buf, size_t count) {
    // TODO: OFFSET BOUND CORNER CASE

    if (buf == NULL || !is_mounted() || fd < 0 || fd >= FS_OPEN_MAX_COUNT || !fd_table[fd].allocated) {
        return FAILURE;
    }

    if(count == 0){
        return 0;
    }

    int block_offset;
    int bytes_write = 0;
    int fat_block_index = -1;
    int actual_block_index;
    int next_block_index;
    int write_amount;
    void * tmp_block;
    if (fd_table[fd].file->data_index == FAT_EOC ) {
        int next_block = find_next_free_block();
        if (next_block == -1)  // No more blocks lefts
            return 0;

        fd_table[fd].file->data_index = next_block;
        fat[next_block] = FAT_EOC;
    }

    tmp_block = malloc(BLOCK_SIZE);

    while(count > 0){
        if(fat_block_index == -1){
            next_block_index = get_data_block_index(fd);
            fat_block_index = next_block_index;
        }
        else{
            next_block_index = fat[fat_block_index];
        }
        if(next_block_index == FAT_EOC){
            next_block_index = find_next_free_block();
            if(next_block_index == -1){
                return bytes_write;
            }
            fat[fat_block_index] = next_block_index;
            fat[next_block_index] = FAT_EOC;
        }
        actual_block_index = fat_block_index + super_block->data_block_start_index;
        block_offset =  fd_table[fd].offset % BLOCK_SIZE;
        if(block_offset == 0){
            if(block_offset + count >= BLOCK_SIZE){
                write_amount = BLOCK_SIZE;
                memcpy(tmp_block + block_offset, buf + bytes_write, BLOCK_SIZE);
            }
            else{
                write_amount = count;
                memcpy(tmp_block + block_offset, buf + bytes_write, count);
            }
        }
        else{
            block_read(actual_block_index, tmp_block);
            if(block_offset + count > BLOCK_SIZE){
                write_amount = BLOCK_SIZE - block_offset;
                memcpy(tmp_block + block_offset, buf + bytes_write, BLOCK_SIZE - block_offset);
            }
            else{
                write_amount = count;
                memcpy(tmp_block + block_offset, buf + bytes_write, count);
            }
        }
        block_write(actual_block_index, tmp_block);
        fd_table[fd].offset += write_amount;
        bytes_write += write_amount;
        count -= write_amount;
    }
    free(tmp_block);
    /*
     * update the size of the file only if the offset of the file is greater than it's previous size
     */
    if((int)fd_table[fd].file->file_size < fd_table[fd].offset){
        fd_table[fd].file->file_size =  fd_table[fd].offset;
    }
    return bytes_write;

}

/**
 * fs_read - Read from a file
 * @fd: File descriptor
 * @buf: Data buffer to be filled with data
 * @count: Number of bytes of data to be read
 *
 * Attempt to read @count bytes of data from the file referenced by file
 * descriptor @fd into buffer pointer by @buf. It is assumed that @buf is large
 * enough to hold at least @count bytes.
 *
 * The number of bytes read can be smaller than @count if there are less than
 * @count bytes until the end of the file (it can even be 0 if the file offset
 * is at the end of the file). The file offset of the file descriptor is
 * implicitly incremented by the number of bytes that were actually read.
 *
 * Return: -1 if no FS is currently mounted, or if file descriptor @fd is
 * invalid (out of bounds or not currently open), or if @buf is NULL. Otherwise
 * return the number of bytes actually read.
 */
int fs_read(int fd, void *buf, size_t count) {
    // TODO: OFFSET BOUND CORNER CASE
    if (buf == NULL || !is_mounted() || fd < 0 || fd >= FS_OPEN_MAX_COUNT || !fd_table[fd].allocated) {
        return FAILURE;
    }

    /*
     * if count == 0 or already at the end of the file
     */
    if(count == 0 || fd_table[fd].offset >= (int)fd_table[fd].file->file_size){
        return 0;
    }

    int bytes_read = 0;
    int fat_block_index = -1;
    int actual_block_index;
    void * tmp_block = malloc(BLOCK_SIZE);
    int block_offset;

    while(count > 0){
        if(fd_table[fd].offset >= (int)fd_table[fd].file->file_size){
            return bytes_read;
        }
        if(fat_block_index == -1){
            fat_block_index = get_data_block_index(fd);
        }
        else{
            fat_block_index = fat[fat_block_index];
        }
        actual_block_index = super_block->data_block_start_index + fat_block_index;
        block_read(actual_block_index, tmp_block);
        block_offset = fd_table[fd].offset % BLOCK_SIZE;
        if(block_offset + count <= BLOCK_SIZE){
            memcpy(buf + bytes_read, tmp_block + block_offset, count);
            fd_table[fd].offset += count;
            bytes_read += count;
            count = 0;
            break;
        }
        else{
            memcpy(buf + bytes_read, tmp_block + block_offset, BLOCK_SIZE - block_offset);
            bytes_read += BLOCK_SIZE - block_offset;
            fd_table[fd].offset += BLOCK_SIZE - block_offset;
            count -= BLOCK_SIZE - block_offset;
        }
    }
    free(tmp_block);
    return bytes_read;
}

int check_consistency() {
    if(strncmp(super_block->signature, SIGNATURE, 8) != 0){
        return FAILURE;
    }
    //
    if (super_block->total_blocks_count != block_disk_count()) {
        return FAILURE;
    }

    int umber_of_blocks_for_FAT;
    int root_directory_index;
    int data_block_start_index;

    if (block_disk_count() < BLOCK_SIZE) {
        umber_of_blocks_for_FAT = 1;
        root_directory_index = 2;
        data_block_start_index = 3;
    }
    else {
        umber_of_blocks_for_FAT = block_disk_count() * 2 / BLOCK_SIZE;
        root_directory_index = block_disk_count() * 2 / BLOCK_SIZE + 1;
        data_block_start_index = block_disk_count() * 2 / BLOCK_SIZE + 2;
    }

    if (super_block->number_of_blocks_for_FAT != umber_of_blocks_for_FAT) {
        return -1;
    }

    if (super_block->root_directory_block_index != root_directory_index) {
        return -1;
    }

    if (super_block->data_block_start_index != data_block_start_index) {
        return -1;
    }

    if (super_block->amount_data_block != block_disk_count() - umber_of_blocks_for_FAT - 2) {
        return -1;
    }

    return SUCCESS;
}

int is_mounted() {
    return block_disk_count() != -1;
}

int is_valid_file_name(const char *file_name) {
    return file_name != NULL && strlen(file_name) + 1 <= FS_FILENAME_LEN;

}

int is_root_full_or_duplicate(const char *file_name) {
    int file_count = 0;
    for (int i = 0; i < FS_FILE_MAX_COUNT; i++) {
        if (root_directory[i].file_name[0] != '\0') {
            ++file_count;
            if (strcmp(root_directory[i].file_name, file_name) == 0) {
                return 1;
            }
        }
    }
    return file_count == FS_FILE_MAX_COUNT;
}

int get_num_free_block() {
    int free_block_count = 0;
    int i = 0;
    while (i < super_block->amount_data_block) {
        if (fat[i] == 0) {
            ++free_block_count;
        }
        ++i;
    }
    return free_block_count;
}

int get_num_free_entry() {
    int num_free_entry = 0;
    int i = 0;
    while (i < FS_FILE_MAX_COUNT) {
        if (root_directory[i].file_name[0] == '\0') {
            ++num_free_entry;
        }
        ++i;
    }
    return num_free_entry;
}

int is_open(const char *file_name) {
    for (int i = 0; i < FS_OPEN_MAX_COUNT; ++i) {
        if (fd_table[i].allocated && strcmp(fd_table[i].file->file_name, file_name) == 0) {
            return 1;
        }
    }
    return 0;
}

int is_exist(const char *file_name) {
    int i = 0;
    while (i < FS_FILE_MAX_COUNT) {
        if (strcmp(root_directory[i].file_name, file_name) == 0) {
            return 1;
        }
        ++i;
    }
    return 0;
}


int get_root_directory_index(const char *file_name) {
    int i = 0;
    while (i < FS_FILE_MAX_COUNT) {
        if (strcmp(root_directory[i].file_name, file_name) == 0) {
            return i;
        }
        ++i;
    }
    return -1;
}

uint16_t get_data_block_index(int fd){
    int offset_chain_map_index = (fd_table[fd].offset) / BLOCK_SIZE;
    uint16_t offset_block_index = fd_table[fd].file->data_index;
    for (int i = 0; i < offset_chain_map_index; i++) {
        offset_block_index = fat[offset_block_index];
    }
    return offset_block_index;
//    return super_block->data_block_start_index + offset_block_index;
}
int find_next_free_block() {
    int i = 0;
    while( i < super_block->amount_data_block){
        if(!fat[i]){
            return i;
        }
        ++i;
    }
    return -1;
}