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

CFLAGS:= -std=c11 -pedantic -pedantic-errors -g -Wall -Werror -Wextra -D_POSIX_C_SOURCE=200112L -fsanitize=address -Wno-unused-parameter -Wno-unused-variable -Wno-unused-function -pthread
SMTPD_CLI:= smtpd
SMTPD_OBJS:= lib/args.o lib/selector.o main.o smtp.o lib/stm.o lib/buffer.o

.PHONY: all clean

all: $(SMTPD_CLI)

$(SMTPD_CLI): $(SMTPD_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

main.o: smtp.h

selector.o: lib/headers/selector.h

args.o : lib/headers/args.h

smtp.o: smtp.h

stm.o: lib/headers/stm.h

buffer.o: lib/headers/buffer.h

clean:
	- rm -rf $(SMTPD_CLI) $(SMTPD_OBJS)
