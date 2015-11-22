SHELL := /bin/bash
CC = gcc
CFLAGS = -fPIC -fno-stack-protector -c -I/usr/local/ssl/include
EDITOR = $${FCEDIT:-$${VISUAL:-$${EDITOR:-nano}}}

pam_riddle: pam_riddle.c
	$(CC) $(CFLAGS) pam_riddle.c
install: pam_riddle.c
	if [ ! -e /lib/security ]; then \
		mkdir /lib/security; \
	fi
	if [ ! -e /usr/share/riddles ]; then \
		mkdir /usr/share/riddles; \
		touch /usr/share/riddles/questions; \
		touch /usr/share/riddles/ansqers; \
		bash ./addriddles.sh ./questions ./answers; \
	fi
	$(CC) -shared pam_riddle.o -o /lib/security/pam_riddle.so -L/usr/local/ssl/lib -lcrypto
clean:
	rm pam_riddle.o
