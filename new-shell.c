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

#define DEBUG_MODE 0

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

#define u32 uint32_t
#define u64 uint64_t

#define MAX_USERNAME_SIZE ((size_t)128)
#define MAX_PROMPT_SIZE (MAX_USERNAME_SIZE + (size_t)128)
#define MAX_ARGS_SIZE ((size_t)128)

#define BUILT_IN_COMMAND ((u32)1)
#define DEFAULT_COMMAND ((u32)2)
#define CD_COMMAND ((u32)4)
#define RM_COMMAND ((u32)8)
#define UNAME_A_COMMAND ((u32)16)

char* err_msg = NULL;

int get_username(char* username) {
	uid_t sys_uid = getuid();
	char* line = NULL;
	size_t line_size = 0;
	FILE* passwd = fopen("/etc/passwd", "r");

	while(getline(&line, &line_size, passwd) != -1) {
		char* user = strtok(line, ":");
		strtok(NULL, ":");
		char* uid = strtok(NULL, ":");

		if(sys_uid == (uid_t)atoi(uid)) {
			if(strlen(user) >= MAX_USERNAME_SIZE) {
				err_msg = "Username too long";
				return -1;
			}
			strcpy(username, user);
			return 0;
		}
	}
	return -1;
}

int build_prompt(char* prompt) {
	char username[MAX_USERNAME_SIZE] = {};
	int ret = get_username(username);
	if (ret) {
		if(!err_msg)
			err_msg = "Could not get username";
		return ret;
	}
	time_t t = time(NULL);
	struct tm tm = *localtime(&t);
	ret = snprintf(prompt, MAX_PROMPT_SIZE, "%s [%02d:%02d:%02d]: ", username, tm.tm_hour, tm.tm_min, tm.tm_sec);
	if(ret < 0) {
		err_msg = "Could not build prompt";
		return ret;
	}
	return 0;
}

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

	if (strcmp(*command, "cd") == 0) {
		*command_flags |= CD_COMMAND | BUILT_IN_COMMAND;
	} else if (strcmp(*command, "rm") == 0) {
		*command_flags |= RM_COMMAND | BUILT_IN_COMMAND;
	} else if (strcmp(*command, "uname") == 0 && args[1] && strcmp(args[1], "-a") == 0) {
		*command_flags |= UNAME_A_COMMAND | BUILT_IN_COMMAND;
	} else {
		*command_flags |= DEFAULT_COMMAND;
	}
}

int _execute_command(u32 command_flags, char* command, char** args) {
	int ret = 0;

	if (DEBUG_MODE) {
		print_info("Executing command %s with args\n", command);
		int i = 0;
		while(args[i]) {
			print_info("arg %d: %s\n", i, args[i]);
			i++;
		}
	}

	print_info("Command Flags: %d\n", command_flags);

	switch (command_flags & ~BUILT_IN_COMMAND) {
		case CD_COMMAND:
			print_info("Executing built-in cd command\n");
			ret = chdir(args[1]);
			if(ret) {
				err_msg = "Could not execute cd command";
				ret = -1;
			}
			break;
		case RM_COMMAND:
			print_info("Executing built-in rm command\n");
			ret = unlink(args[1]);
			if(ret) {
				err_msg = "Could not execute remove command";
				ret = -1;
			}
			break;
		case UNAME_A_COMMAND:
			struct utsname uts;

			print_info("Executing built-in uname -a command\n");
			uname(&uts);
			printf("%s %s %s %s %s GNU/Linux\n", uts.sysname, uts.nodename, uts.release, uts.version, uts.machine);

			if(ret) {
				err_msg = "Could not execute uname -a command";
				ret = -1;
			}
			break;
		default:
			ret = execv(command, args);
			if(ret) {
				err_msg = "Could not execute command";
				ret =  -1;
			}
			break;
	}

	return ret;
}

int execute_command(u32 command_flags, char* command, char** args) {
	int ret = 0;
	ret = _execute_command(command_flags, command, args);
	if(ret) {
		printf("%s\n", err_msg ? err_msg : "Could not execute command\n");
	}

	free(command);
	return ret;

}

int main()
{
	int ret = 0;

	char prompt[MAX_PROMPT_SIZE] = {};

	char* command_line = NULL;
	char* command = NULL;

	char* args[MAX_ARGS_SIZE] = {};

	using_history();

	while(1) {
		u32 command_flags = 0;
		pid_t child_pid = 0;

		ret = build_prompt(prompt);
		if(ret)
			goto error;

		ret = read_command_line(&command_line, prompt);

		if(ret) {
			err_msg = "Could not read command line";
			goto error;
		}

		parse_command(command_line, &command, args, &command_flags);

		if(command_flags & BUILT_IN_COMMAND) {
			execute_command(command_flags, command, args);
			continue;
		}

		if((child_pid = fork()) == 0) {
			ret = execute_command(command_flags, command, args);
			return ret;
		}

		waitpid(child_pid, NULL, 0);
	}

	return 0;

error:
	print_error(err_msg);
	return ret;
}
