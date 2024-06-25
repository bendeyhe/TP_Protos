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
CFLAGS:= -std=c11 -pedantic -pedantic-errors -g -Og -Wall -Werror -Wextra -D_POSIX_C_SOURCE=200112L -fsanitize=address -Wno-unused-parameter -Wno-unused-variable -Wno-unused-function -pthread

# Fuentes
SERVER_SOURCES:= $(wildcard src/lib/*.c src/*.c src/manager/server/*.c)
CLIENT_SOURCES:= $(wildcard src/manager/client/*.c)
TEST_SOURCES:= $(wildcard test/*.c)

# Objetos
SERVER_OBJS:= $(SERVER_SOURCES:src/%.c=obj/%.o)
CLIENT_OBJS:= $(CLIENT_SOURCES:src/%.c=obj/%.o)
TEST_OBJS:= $(TEST_SOURCES:test/%.c=obj/%.o)

# Archivos de salida
OUTPUT_FOLDER:=./bin
OBJ_FOLDER:=./obj
TEST_FOLDER:=./src/test

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
	- rm -rf $(OUTPUT_FOLDER) $(OBJ_FOLDER) src/test/*.o stress_test stress smtpd client

stress: src/test/stress_test.o
	$(CC) $(CFLAGS) -o $@ $^

stress_test: stress
	./stress