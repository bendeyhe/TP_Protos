#########
# FLAGS #
#########
# -Wall 						: Enable all warnings
# -Wextra 						: Extra warnings
# -Werror 						: Treat all warnings as errors
# -g							: Add debugging symbols
# -fsanitize=address 			: Address sanitizer (libasan)
# -std=c11						: Use C11
# -D_POSIX_C_SOURCE=200112L 	: Posix version

#CFLAGS:= -std=c11 -pedantic -pedantic-errors -g -Og -Wall -Werror -Wextra -D_POSIX_C_SOURCE=200112L -fsanitize=address -Wno-unused-parameter -Wno-unused-variable -Wno-unused-function -pthread
#SMTPD_CLI:= smtpd
#SMTPD_OBJS:= lib/args.o lib/selector.o main.o smtp.o lib/stm.o lib/buffer.o lib/request.o lib/data.o lib/stats.o
#
#.PHONY: all clean test
#
#all: $(SMTPD_CLI)
#
#$(SMTPD_CLI): $(SMTPD_OBJS)
#	$(CC) $(CFLAGS) -o $@ $^
#
#main.o: src/smtp.h
#
#selector.o: src/lib/headers/selector.h
#
#args.o : src/lib/headers/args.h
#
#smtp.o: src/smtp.h lib/headers/stm.h lib/headers/buffer.h lib/headers/request.h lib/headers/data.h lib/headers/stats.h
#
#stm.o: src/lib/headers/stm.h
#
#buffer.o: src/lib/headers/buffer.h
#
#request.o: src/lib/headers/request.h lib/headers/buffer.h
#
#data.o: src/lib/headers/data.h lib/headers/buffer.h
#
#stats.o: src/lib/headers/stats.h
#
#clean:
#	- rm -rf $(SMTPD_CLI) $(SMTPD_OBJS) request_test
#
#request_test: test/request_test.o src/lib/request.o lib/buffer.o
#	$(CC) $(CFLAGS) -o $@ $^ -pthread -lcheck_pic -pthread -lrt -lm -lsubunit
#
#test: request_test
#	./request_test

# VERSION 2 DEL MAKEFILE

CFLAGS:= -std=c11 -pedantic -pedantic-errors -g -Og -Wall -Werror -Wextra -D_POSIX_C_SOURCE=200112L -fsanitize=address -Wno-unused-parameter -Wno-unused-variable -Wno-unused-function -pthread

# Fuentes
SERVER_SOURCES:= $(wildcard src/lib/*.c src/*.c src/manager/server/*.c)
CLIENT_SOURCES:= $(wildcard src/manager/client/*.c)

# Objetos
SERVER_OBJS:= $(SERVER_SOURCES:src/%.c=obj/%.o)
CLIENT_OBJS:= $(CLIENT_SOURCES:src/%.c=obj/%.o)

# Archivos de salida
OUTPUT_FOLDER:=./bin
OBJ_FOLDER:=./obj

# Archivos de salida
SERVER_OUTPUT_FILE:=smtpd
CLIENT_OUTPUT_FILE:=client

.PHONY: all server client clean

all: server client

server: $(SERVER_OBJS)
	$(CC) $(CFLAGS) $(SERVER_OBJS) -o $(SERVER_OUTPUT_FILE)

client: $(CLIENT_OBJS)
	$(CC) $(CFLAGS) $(CLIENT_OBJS) -o $(CLIENT_OUTPUT_FILE)

obj/lib/%.o: src/lib/%.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

obj/%.o: src/%.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

obj/manager/server/%.o: src/manager/server/%.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

obj/manager/client/%.o: src/manager/client/%.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	- rm -rf $(OUTPUT_FOLDER) $(OBJ_FOLDER)