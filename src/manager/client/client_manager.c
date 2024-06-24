#include "client_manager.h"
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

enum status {
    OK = 0x00,
    UNAUTHORIZED = 0x01,
    INVALID_COMMAND = 0x02,
    INVALID_VERSION = 0x03,
    INVALID_REQUEST = 0x04,
    UNEXPECTED_ERROR = 0x05,
    SAVED_FOR_FUTURE_USE = 0x06
};

void init_buffer(char *buffer, uint8_t cmd) {
    uint16_t signature = htons(SIGNATURE);

    static u_int16_t request_id = 0;
    request_id++;
    request_id = htons(request_id);
    uint16_t net_request_id = htons(request_id);
    uint32_t user = htonl(USER);
    uint32_t pass = htonl(PASS);

    buffer[0] = (signature >> 8) & 0xFF;
    buffer[1] = signature & 0xFF;
    buffer[2] = VERSION;
    buffer[3] = (net_request_id >> 8) & 0xFF;
    buffer[4] = net_request_id & 0xFF;
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

bool check_response(uint8_t *response) {
    uint16_t signature = ntohs(*(uint16_t *) response);
    uint8_t version = response[2];
    //uint16_t identifier = ntohs(*(uint16_t *) (response + 3));
    uint8_t status = response[5];

    if (signature != SIGNATURE || version != VERSION) {
        return false;
    }
    return status <= UNEXPECTED_ERROR;
}

void print_response(uint8_t *response, uint8_t cmd) {
    switch (response[5]) {
        case OK:
            break;
        case UNAUTHORIZED:
            fprintf(stderr, "Unauthorized\n");
            return;
        case INVALID_COMMAND:
            fprintf(stderr, "Invalid command\n");
            return;
        case INVALID_VERSION:
            fprintf(stderr, "Invalid version\n");
            return;
        case INVALID_REQUEST:
            fprintf(stderr, "Invalid request\n");
            return;
        case UNEXPECTED_ERROR:
            fprintf(stderr, "Unexpected error\n");
            return;
    }

    uint32_t data = 0;
    for (int i = 0; i < 4; i++) {
        data |= (uint32_t) response[6 + i] << (8 * i);
    }

    switch (cmd){
        case HI_CO:
            printf("Historical connection quantity: %" PRIu32 "\n", data);
            break;
        case CU_CO:
            printf("Current connection quantity: %" PRIu32 "\n", data);
            break;
        case BY_SE:
            printf("Bytes sent: %" PRIu32 "\n", data);
            break;
        case BY_RE:
            printf("Bytes received: %" PRIu32 "\n", data);
            break;
        case AL_BY:
            printf("All bytes: %" PRIu32 "\n", data);
            break;
        case HELP:
            printf("COMMANDS:\n");
            printf("- HI_CO      Get historical connection quantity\n");
            printf("- CU_CO      Get current connection quantity\n");
            printf("- BY_SE      Get bytes sent\n");
            printf("- BY_RE      Get bytes received\n");
            printf("- AL_BY      Get all bytes\n");
            break;
    }
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

    if (cmd == (uint8_t) -1) {
        fprintf(stderr, "Invalid command, use HELP for more information\n");
        return 1;
    }

    uint8_t buffer[REQUEST_SIZE];
    init_buffer((char *) buffer, cmd);

    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    if(inet_pton(AF_INET6, host, &addr.sin6_addr) != 1){
        perror("inet_pton");
        return 1;
    }
    addr.sin6_port = htons(atoi(port));

    const int client = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

    if (client < 0) {
        perror("socket");
        return 1;
    }

    setsockopt(client, SOL_SOCKET, SO_REUSEADDR, &(int) {1}, sizeof(int));
    setsockopt(client, IPPROTO_IPV6, IPV6_V6ONLY, &(int) {0}, sizeof(int));

    struct timeval tv = {5, 0};
    setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (const char *) &tv, sizeof(struct timeval));

    ssize_t num_bytes = sendto(client, buffer, REQUEST_SIZE, 0, (struct sockaddr *) &addr, sizeof(addr));

    if (num_bytes != REQUEST_SIZE) {
        perror("sendto");
        close(client);
        return 1;
    }

    struct sockaddr_storage from;
    socklen_t from_len = sizeof(from);
    uint8_t response[RESPONSE_SIZE];

    num_bytes = recvfrom(client, response, RESPONSE_SIZE, 0, (struct sockaddr *) &from, &from_len);

    // verifico si la respuesta es correcta
    if (!check_response(response)) {
        fprintf(stderr, "Unexpected response\n");
        close(client);
        return 1;
    }

    print_response(response, cmd);

    close(client);
    return 0;
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