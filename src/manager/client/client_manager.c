#include "client_manager.h"
#include <stdio.h>


/**
 * Request:
 *
 * Protocol signature: 2 bytes (0xFF 0xFE)
 * Version: 1 byte (0x00)
 * Identifier: 2 bytes
 * Auth: 8 bytes (user/pass, token)
 * Command: 1 byte:
 * - 0x00: Get historical connection quantity
 * - 0x01: Get current connection quantity
 * - 0x02: Get bytes sent
 * - 0x03: Get bytes received
 * - 0x04: Get all bytes
 */
/*
struct request_datagram {
    uint8_t signature[2];
    uint8_t version;
    uint8_t identifier[2];
    uint8_t auth[8];
    uint8_t command;
};
 */

/**
 * Response:
 *
 * Protocol signature: 2 bytes (0xFF 0xFE)
 * Version: 1 byte (0x00)
 * Identifier: 2 bytes
 * Status: 1 byte:
 * - 0x00: OK
 * - 0x01: Unauthorized
 * - 0x02: Invalid command
 * - 0x03: Invalid version
 * - 0x04: Invalid request
 * - 0x05: Unexpected error
 * - 0x06: Saved for future use
 * Data: 8 bytes:
 * - Quantity
 */
/*
struct response_datagram {
    uint8_t signature[2];
    uint8_t version;
    uint8_t identifier[2];
    uint8_t status;
    uint8_t data[8];
};
 */

// HI_CO, CU_CO, BY_SE, BY_RE, AL_BY
enum command {
    HI_CO = 0x00,
    CU_CO = 0x01,
    BY_SE = 0x02,
    BY_RE = 0x03,
    AL_BY = 0x04,
    HELP = 0x05
};

void init_buffer(char *buffer, uint8_t cmd) {
    uint16_t signature = htons(SIGNATURE);

    static request_id = 0;
    request_id++;
    request_id = htons(request_id);
    uint32_t user = htonl(USER); 11111111
    uint32_t pass = htonl(PASS);

    buffer[0] = (signature >> 8) & 0xFF;
    buffer[1] = signature & 0xFF;
    buffer[2] = VERSION;
    buffer[3] = (request_id >> 8) & 0xFF;
    buffer[4] = request_id & 0xFF;
    buffer[5] = (user >> 24) & 0xFF;
    buffer[6] = (user >> 16) & 0xFF;
    buffer[7] = (user >> 8) & 0xFF;
    buffer[8] = user & 0xFF;
    buffer[9] = (pass >> 24) & 0xFF;
    buffer[10] = (pass >> 16) & 0xFF;
    buffer[11] = (pass >> 8) & 0xFF;
    buffer[12] = pass & 0xFF;
    buffer[13] = cmd;
}

uint8_t get_command(const char *command) {
    if (strcmp(command, "HI_CO") == 0) {
        return HI_CO;
    } else if (strcmp(command, "CU_CO") == 0) {
        return CU_CO;
    } else if (strcmp(command, "BY_SE") == 0) {
        return BY_SE;
    } else if (strcmp(command, "BY_RE") == 0) {
        return BY_RE;
    } else if (strcmp(command, "AL_BY") == 0) {
        return AL_BY;
    } else if (strcmp(command, "HELP") == 0) {
        return HELP;
    }
    return -1;
}

int main(int argc, char *argv[]) {
    if (argc < 4 || argc > 4) {
        fprintf(stderr, "Usage: %s [HOST] [PORT] [COMMAND]\n", argv[0]);
        return 1;
    }

    const char *host = argv[1];
    const char *port = argv[2];
    const char *command = argv[3];

    uint8_t cmd = get_command(command);

    if(cmd == -1) {
        fprintf(stderr, "Invalid command, use HELP for more information\n");
        return 1;
    }

    uint8_t buffer[REQUEST_SIZE];
    init_buffer(buffer, cmd);

    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_addr = in6addr_any;
    addr.sin6_port = htons(atoi(port));

    const int client = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

    if (client < 0) {
        perror("socket");
        return 1;
    }





}

/**
 * [HOST] [PORT] [COMMAND]
 *
 * COMMANDS:
 * - HI_CO      Get historical connection quantity
 * - CU_CO      Get current connection quantity
 * - BY_SE      Get bytes sent
 * - BY_RE      Get bytes received
 * - AL_BY      Get all bytes
 * - HELP      Show this help
 *
 * ./monitor
 *
 * Ejemplo:
 * nc localhost 7374 HI_CO
*/