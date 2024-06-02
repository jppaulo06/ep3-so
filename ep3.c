#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
#include <curses.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/utsname.h>

#include <readline/readline.h>
#include <readline/history.h>

#define DEBUG_MODE 1

#define print_info(info, ...) \
	do { \
		if(DEBUG_MODE) { \
			fprintf(stderr, "[INFO] File: %s, Line: %d: ", __FILE__, __LINE__); \
			fprintf(stderr, info, ##__VA_ARGS__); \
		} \
	} while(0)

#define print_error(error_message) \
	do { \
		if(DEBUG_MODE) \
			fprintf(stderr, "[ERROR] File: %s, Line: %d: ", __FILE__, __LINE__); \
		perror(error_message); \
	} while(0)

#define TODO_COMMAND() \
	do { \
		err_msg = "Command not implementd yet :/"; \
		return -1; \
	} while(0)

#define u32 uint32_t
#define u64 uint64_t

#define MAX_ARGS_SIZE ((size_t)128)

#define BUILT_IN_COMMAND ((u32)1)
#define DEFAULT_COMMAND ((u32)2)
#define MOUNT_COMMAND ((u32)4)
#define CREATE_DIR_COMMAND ((u32)8)
#define CD_COMMAND ((u32)16)

char* err_msg = NULL;

/*
 * JP FILESYSTEM
 *
 * Creating filesystem with "monta" results in 128MB of disk
 * Each block has 4KB
 * Directories are inside the data section
 *
 * METADATA | BITMAP | FAT TABLE | DATA
 *
 * First Section - Metadata
 *	4 bytes for the size of the disk Size of disk
 *
 *	4 bytes for the amount of blocks of the data section
 *
 *	4 bytes for the index of the bitmap
 *	4 bytes for the index of the FAT table
 *      4 bytes for the index of the first block of the data section
 *
 *      4 bytes for the index of the root directory
 *      4 bytes for creation time
 */

#define BLOCK_SIZE (1 << 12) /* 4KB or 2^12 bytes */
#define DEFAULT_DISK_SIZE (1 << 27) /* 128 MB or 2^27 bytes */
#define MAX_DISK_SIZE DEFAULT_DISK_SIZE
#define MAX_BITMAP_SIZE (1 + (MAX_DISK_SIZE / BLOCK_SIZE) / BYTE_SIZE_IN_BITS)
#define MAX_DIR_DEPTH 64
#define WORD_SIZE 4
#define BYTE_SIZE_IN_BITS 8

struct disk {
	bool mounted;
	char* path;

	FILE* file;
	u32 size;
	u32 block_amount;
	u32 bitmap_index;
	u32 fat_index;
	u32 data_index;
	u32 root_index;
	u32 creation_time;

	u32 bitmap_size;
	u32 bitmap[MAX_BITMAP_SIZE];
};

#define META_DISK_SIZE 4
#define META_BLOCK_AMOUNT 4
#define META_BITMAP_INDEX 4
#define META_FAT_INDEX 4
#define META_DATA_INDEX 4
#define META_ROOT_INDEX 4
#define META_CREATION_TIME 4
#define META_SIZE (META_DISK_SIZE + META_BLOCK_AMOUNT + META_BITMAP_INDEX + \
		   META_FAT_INDEX + META_DATA_INDEX + META_ROOT_INDEX + \
		   META_CREATION_TIME)

/*
 * Second Section - Bitmap
 *	1 bit per block to store if it is free or not
 *	0 if it is free
 *	1 if it is not free
 */


/*
 * Third Section - FAT Table
 *	4 bytes per block to store the index of the next block
 *	0xFFFFFFFF if it is the last block
 *	0xFFFFFFFE if it is a free block
 *
 * Third Section - Data
 *     4KB per block
 */

#define FAT_INDEX_SIZE 4
#define FAT_LAST_BLOCK 0xFFFFFFFF
#define FAT_FREE_BLOCK 0xFFFFFFFE

 /*
 * Directory
 * 	Each directory is represented as a file in the data section and in the
 * 	FAT table.
 *
 * 	Representation of a directory:
 * 		- 4 bytes for the ammount of entries
 * 		For each entry:
 *			- 1 byte for the type of the entry
 *			- 64 bytes for the name of the entry in ascii
 *			- 4 bytes for the index of the first block of the entry
 *			- 4 bytes for creation time
 *			- 4 bytes for modification time
 *			- 8 bytes for the size of the entry
 */

#define DIR_ENTRIES_AMOUNT_SIZE 4
#define DIR_TYPE_SIZE 4
#define DIR_NAME_SIZE 64
#define DIR_ENTRY_BLOCK_INDEX_SIZE 4
#define DIR_CREATION_TIME_SIZE 4
#define DIR_MODIFICATION_TIME_SIZE 4
#define DIR_ENTRY_SIZE_SIZE 4

#define DIR_ENTRY_SIZE (DIR_TYPE_SIZE + DIR_NAME_SIZE + DIR_ENTRY_BLOCK_INDEX_SIZE + \
			DIR_CREATION_TIME_SIZE + DIR_MODIFICATION_TIME_SIZE + \
			DIR_ENTRY_SIZE_SIZE)

#define DIR_DIR_TYPE 1
#define DIR_FILE_TYPE 2

/*
 * ============================================================================
 *				FILESYSTEM FUNCTIONS
 * ============================================================================
 */

/* Mount command */

int fill_disk_word(struct disk* disk, u32 offset, u32 value, u32 amount) {
	int ret = 0;
	u32 i = 0;

	ret = fseek(disk->file, offset, SEEK_SET);
	if(ret) {
		print_error("Could not seek to the offset");
		return ret;
	}

	while(i < amount) {
		ret = putw(value, disk->file);
		if(ret == EOF) {
			print_error("Could not write to disk");
			return ret;
		}
		i++;
	}

	ret = fflush(disk->file);
	if(ret) {
		print_error("Could not flush the file");
		return ret;
	}

	return ret;
}

u32 nearest_multiple_from_divisor(u32 value, u32 divisor) {
	return (value / divisor) * divisor;
}

void init_metadata(struct disk* disk) {
	disk->size = DEFAULT_DISK_SIZE;
	/* size = meta + (1 / 8) * block_amount + a * fat + b * data */
	disk->block_amount = 8 * ((disk->size - META_SIZE) / (1 + 8 * FAT_INDEX_SIZE + 8 * BLOCK_SIZE));
	disk->bitmap_index = META_SIZE;
	disk->fat_index = disk->bitmap_index + disk->block_amount / WORD_SIZE;
	disk->data_index = disk->fat_index + disk->block_amount * FAT_INDEX_SIZE;
	disk->root_index = disk->data_index;
	disk->creation_time = time(NULL);
}

int write_metadata(struct disk* disk) {
	int ret = 0;

	ret = fseek(disk->file, 0, SEEK_SET);
	if(ret) {
		print_error("Could not seek to the beginning of the file");
		return ret;
	}

	ret = putw(disk->size, disk->file);
	if(ret == EOF)
		goto write_metadata_error;

	ret = putw(disk->block_amount, disk->file);
	if(ret == EOF)
		goto write_metadata_error;

	ret = putw(disk->bitmap_index, disk->file);
	if(ret == EOF)
		goto write_metadata_error;

	ret = putw(disk->fat_index, disk->file);
	if(ret == EOF)
		goto write_metadata_error;

	ret = putw(disk->data_index, disk->file);
	if(ret == EOF)
		goto write_metadata_error;

	ret = putw(disk->root_index, disk->file);
	if(ret == EOF)
		goto write_metadata_error;

	ret = putw(disk->creation_time, disk->file);
	if(ret == EOF)
		goto write_metadata_error;

	return ret;

write_metadata_error:
	print_error("Could not write metadata property to disk");
	return ret;
}

int write_to_disk(struct disk* disk, u32 index, void* data, u32 size) {
	long ret = 0;

	ret = fseek(disk->file, index, SEEK_SET);
	if(ret) {
		print_error("Could not seek to the index");
		return ret;
	}

	ret = fwrite(data, sizeof(char), size, disk->file);
	if((u64) ret != size) {
		print_error("Could not write to disk");
		return ret;
	}

	return ret;
}

int create_disk(struct disk* disk, char* path) {
	int ret = 0;

	disk->file = fopen(path, "w+");
	if(disk->file == NULL) {
		print_error("Could not open file for writing");
		return ret;
	}

	init_metadata(disk);

	ret = ftruncate(fileno(disk->file), disk->size);
	if(ret) {
		print_error("Could not truncate file");
		return ret;
	}

	ret = write_metadata(disk);
	if(ret) {
		print_error("Could not write metadata");
		return ret;
	}

	ret = fill_disk_word(disk, disk->fat_index, FAT_FREE_BLOCK, disk->block_amount);
	if(ret) {
		print_error("Could not fill the FAT table");
		return ret;
	}

	ret = fill_disk_word(disk, disk->data_index, 0, (disk->block_amount * BLOCK_SIZE) / WORD_SIZE);
	if(ret) {
		print_error("Could not fill the data section");
		return ret;
	}

	return ret;
}

int read_metadata(struct disk* disk) {
	int ret = 0;

	ret = fseek(disk->file, 0, SEEK_SET);
	if(ret) {
		print_error("Could not seek to the beginning of the file");
		return ret;
	}

	ret = getw(disk->file);
	if(ret == EOF)
		goto read_metadata_error;
	disk->size = ret;

	ret = getw(disk->file);
	if(ret == EOF)
		goto read_metadata_error;
	disk->block_amount = ret;

	ret = getw(disk->file);
	if(ret == EOF)
		goto read_metadata_error;
	disk->bitmap_index = ret;

	ret = getw(disk->file);
	if(ret == EOF)
		goto read_metadata_error;
	disk->fat_index = ret;

	ret = getw(disk->file);
	if(ret == EOF)
		goto read_metadata_error;
	disk->data_index = ret;

	ret = getw(disk->file);
	if(ret == EOF)
		goto read_metadata_error;
	disk->root_index = ret;

	ret = getw(disk->file);
	if(ret == EOF)
		goto read_metadata_error;
	disk->creation_time = ret;

	ret = 0;

	return ret;

read_metadata_error:
	print_error("Could not read metadata property from disk");
	return ret;
}

int parse_disk(struct disk* disk, char* path) {
	int ret = 0;

	disk->file = fopen(path, "r+");
	if(disk->file == NULL) {
		print_error("Could not open file for reading");
		return ret;
	}

	ret = read_metadata(disk);
	if(ret) {
		print_error("Could not read metadata");
	}

	return ret;
}

int read_bitmap(struct disk* disk) {
	int ret;
	u32 i = 0;

	ret = fseek(disk->file, disk->bitmap_index, SEEK_SET);
	if(ret) {
		print_error("Could not seek to the bitmap index");
		return ret;
	}

	disk->bitmap_size = disk->block_amount / BYTE_SIZE_IN_BITS;
	for(i = 0; i < disk->bitmap_size; i++) {
		ret = fgetc(disk->file);
		if(ret == EOF) {
			print_error("Could not read bitmap");
			return ret;
		}
		disk->bitmap[i] = ret;
	}

	return 0;
}

int read_disk(char* path, struct disk* disk) {
	int ret = 0;

	print_info("Mounting filesystem %s\n", path);

	if (access(path, F_OK) == -1) {
		ret = create_disk(disk, path);
		if(ret) {
			print_error("Could not create disk");
			return ret;
		}
	}
	else {
		ret = parse_disk(disk, path);
		if(ret) {
			print_error("Could not parse disk");
			return ret;
		}
	}

	read_bitmap(disk);

	return ret;
}

void print_info_disk_meta(struct disk* disk) {
	print_info("Disk Metadata:\n");
	print_info("Size: %d\n", disk->size);
	print_info("Block Amount: %d\n", disk->block_amount);
	print_info("Bitmap Index: %d\n", disk->bitmap_index);
	print_info("FAT Index: %d\n", disk->fat_index);
	print_info("Data Index: %d\n", disk->data_index);
	print_info("Root Index: %d\n", disk->root_index);
	print_info("Creation Time: %d\n", disk->creation_time);
}

/* Create directory command */

long get_free_block(struct disk* disk) {
	u32 i = 0;
	u32 j = 0;
	u32 k = 0;

	for(i = 0; i < disk->bitmap_size; i++) {
		if(disk->bitmap[i] != 0xFF) {
			for(j = 0; j < BYTE_SIZE_IN_BITS; j++) {
				if(!(disk->bitmap[i] & (1 << j))) {
					return i * BYTE_SIZE_IN_BITS + j;
				}
			}
		}
	}

	return EOF;
}

int update_bitmap(struct disk* disk) {
	int ret = 0;

	ret = fseek(disk->file, disk->bitmap_index, SEEK_SET);
	if(ret) {
		print_error("Could not seek to the bitmap index");
		return ret;
	}

	ret = fwrite(disk->bitmap, sizeof(char), disk->bitmap_size, disk->file);
	if((u64) ret != disk->bitmap_size) {
		print_error("Could not write to disk");
		return ret;
	}

	ret = fflush(disk->file);
	if(ret) {
		print_error("Could not flush the file");
		return ret;
	}

	return ret;
}

int use_block(struct disk* disk, (u32)block) {
	u32 i = block / BYTE_SIZE_IN_BITS;
	u32 j = block % BYTE_SIZE_IN_BITS;
	disk->bitmap[i] |= (1 << j);

	return update_bitmap(disk);
}

void get_path_list(char* path, char** path_list, u32* path_list_size) {
	u32 i = 0;
	char* token = NULL;

	token = strtok(path, "/");
	while(token != NULL) {
		path_list[i] = token;
		i++;
		token = strtok(NULL, "/");
	}

	*path_list_size = i;
}

long search_dir_index(struct disk* disk, char** path_list, u32 depth) {
	int ret;

	u32 dir_index = disk->root_index;
	u32 entries_amount;
	u32 entry_type;
	char entry_name[DIR_NAME_SIZE];
	u32 entry_block_index;

	u32 i = 0;
	u32 j = 0;

	while(i < depth) {
		entries = 0;
		ret = fseek(disk->file, dir_index, SEEK_SET);
		if(ret) {
			print_error("Could not seek to the directory index");
			return ret;
		}

		ret = fread(&entries_amount, sizeof(u32), 1, disk->file);
		if(ret == EOF) {
			print_error("Could not read the amount of entries");
			return ret;
		}

		for(j = 0; j < entries_amount; j++) {
			ret = fseek(disk->file, dir_index + j * DIR_ENTRY_SIZE, SEEK_SET);
			if(ret) {
				print_error("Could not seek to the entry index");
				return ret;
			}

			ret = fread(&entry_type, sizeof(u32), 1, disk->file);
			if(ret == EOF) {
				print_error("Could not read the entry type");
				return ret;
			}

			if(entry_type != DIR_DIR_TYPE)
				continue;

			ret = fread(entry_name, sizeof(char), DIR_NAME_SIZE, disk->file);
			if(ret == EOF) {
				print_error("Could not read the entry name");
				return ret;
			}

			if(strcmp(entry_name, path_list[i]) != 0)
				continue;

			ret = fread(&entry_block_index, sizeof(u32), 1, disk->file);
			if(ret == EOF) {
				print_error("Could not read the entry block");
				return ret;
			}

			dir_index = disk->data_index + entry_block * BLOCK_SIZE;
			break;
		}

		if(j == entries_amount) {
			print_error("Could not find the directory");
			return -1;
		}
	}

	return block;
}

int create_dir(struct disk* disk, char* path) {
	long ret = 0;
	char path_list[MAX_DIR_DEPTH][DIR_NAME_SIZE];
	u32 path_list_size = 0;
	u32 block, block_index;

	ret = get_free_block(disk);
	if(ret == EOF) {
		print_error("No free blocks available");
		return ret;
	}
	block = (u32) ret;

	get_path_list(path, path_list, &path_list_size);
	block_index = disk->data_index + free_block * BLOCK_SIZE;

	ret = use_block(disk, block);
	if(ret) {
		print_error("Could not use block");
		return ret;
	}
}

/*
 * ============================================================================
 *				SHELL FUNCTIONS
 * ============================================================================
 */

int read_command_line(char** command_line, char* prompt) {
	*command_line = readline(prompt);
	add_history(*command_line);

	if(!command_line)
		return -1;

	print_info("Read command line: %s\n", *command_line);

	return 0;
}

void build_args(char* command, char** args) {
	char* new_arg = NULL;
	size_t built_args = 0;

	args[built_args] = command;
	built_args++;

	while((new_arg = strtok(NULL, " ")) != NULL && built_args < MAX_ARGS_SIZE - 1) {
		args[built_args] = new_arg;
		built_args++;
	}

	args[built_args] = NULL;
}

void parse_command(char* command_line, char** command, char** args, u32 *command_flags) {
	*command = strtok(command_line, " ");
	build_args(*command, args);

	if (strcmp(*command, "monta") == 0) {
		*command_flags |= MOUNT_COMMAND | BUILT_IN_COMMAND;
	} else if (strcmp(*command, "criadir") == 0) {
		*command_flags |= CREATE_DIR_COMMAND | BUILT_IN_COMMAND;
	} else if (strcmp(*command, "cd") == 0) {
		*command_flags |= CD_COMMAND | BUILT_IN_COMMAND;
	} else {
		*command_flags |= DEFAULT_COMMAND;
	}
}

int _execute_command(struct disk* disk, u32 command_flags, char* command, char** args) {
	int ret;

	if (DEBUG_MODE) {
		print_info("Executing command %s with args\n", command);
		int i = 0;
		while(args[i]) {
			print_info("arg %d: %s\n", i, args[i]);
			i++;
		}
	}

	print_info("Command Flags: %d\n", command_flags);

	switch (command_flags) {

		case BUILT_IN_COMMAND | MOUNT_COMMAND:
			print_info("Executing mount command\n");

			ret = read_disk(args[1], disk);
			if(ret) {
				err_msg = "Could not execute mount filesystem";
				return ret;
			}

			print_info("Disk mounted successfully!\n");
			print_info_disk_meta(disk);
			break;

		case BUILT_IN_COMMAND | CREATE_DIR_COMMAND:
			print_info("Executing create dir command\n");

			if(!disk->mounted) {
				err_msg = "Disk not mounted";
				return -1;
			}

			ret = create_dir(disk, args[1]);
			if(ret) {
				err_msg = "Could not create directory";
				return ret;
			}

			break;

		case BUILT_IN_COMMAND | CD_COMMAND:
			print_info("Executing built-in cd command\n");
			ret = chdir(args[1]);
			if(ret) {
				err_msg = "Could not execute cd command";
				return ret;
			}
			break;

		case DEFAULT_COMMAND:
			ret = execvp(command, args);
			if(ret) {
				err_msg = "Could not execute command";
				return ret;
			}
			break;

		default:
			err_msg = "Command error. This should not happen.";
			return -1;
	}

	return 0;
}

int execute_command(struct disk* disk, u32 command_flags, char* command, char** args) {
	int ret = 0;
	ret = _execute_command(disk, command_flags, command, args);
	if(ret) {
		printf("%s\n", err_msg ? err_msg : "Could not execute command\n");
	}

	free(command);
	return ret;

}

int main()
{
	int ret = 0;
	char* prompt = "{ep3}: ";
	char* command_line = NULL;
	char* command = NULL;
	char* args[MAX_ARGS_SIZE] = {};
	struct disk disk = {};

	using_history();

	while(1) {
		u32 command_flags = 0;
		pid_t child_pid = 0;

		ret = read_command_line(&command_line, prompt);

		if(ret) {
			err_msg = "Could not read command line";
			goto error;
		}

		parse_command(command_line, &command, args, &command_flags);

		if(command_flags & BUILT_IN_COMMAND) {
			execute_command(&disk, command_flags, command, args);
			continue;
		}

		if((child_pid = fork()) == 0) {
			ret = execute_command(&disk, command_flags, command, args);
			return ret;
		}

		waitpid(child_pid, NULL, 0);
	}

	return 0;

error:
	print_error(err_msg);
	return ret;
}
