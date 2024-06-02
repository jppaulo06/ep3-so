CFLAGS = -Wall -Wextra

all: ep3

ep3: ep3.c
	gcc $(CFLAGS) ep3.c -lreadline -o ep3

clean:
	@if [ -f ep3 ]; then rm ep3; fi
