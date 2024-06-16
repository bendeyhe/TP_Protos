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

CFLAGS:= -std=c11 -pedantic -pedantic-errors -g -Wall -Werror -Wextra -D_POSIX_C_SOURCE=200112L -fsanitize=address
SMTPD_CLI:= smtpd
SMTPD_OBJS:= args.o main.o

.PHONY: all clean

all: $(SMTPD_CLI)

args.o : args.h

$(SMTPD_CLI): $(SMTPD_OBJS)
	$(CC) $(CFLAGS) $(SMTPD_OBJS) -o $(SMTPD_CLI)

clean:
	- rm -rf $(SMTPD_CLI) $(SMTPD_OBJS)
