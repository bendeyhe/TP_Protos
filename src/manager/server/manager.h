#ifndef MANAGER_H
#define MANAGER_H
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <string.h>
#include <sys/time.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdio.h>

#include "../../lib/headers/selector.h"
#define SIGNATURE 0xCAFE
#define VERSION 0x00
#define USER 0xC0FFEE00
#define PASS 0xCAFEBABE
#define REQUEST_SIZE 14
#define RESPONSE_SIZE 14

enum status {
    OK = 0x00,
    UNAUTHORIZED = 0x01,
    INVALID_COMMAND = 0x02,
    INVALID_VERSION = 0x03,
    INVALID_REQUEST = 0x04,
    UNEXPECTED_ERROR = 0x05,
    SAVED_FOR_FUTURE_USE = 0x06
};


void manager_passive_accept2(struct selector_key *key);

#endif //MANAGER_H
