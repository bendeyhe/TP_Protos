#include "manager.h"
#include "../../lib/headers/selector.h"
#include "../../lib/headers/stm.h"
#include "../../lib/headers/stats.h"
#include <sys/socket.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

/**
 * Request:
 *
 * Protocol signature: 2 bytes (0xCA 0xFE)
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
/**
* Response:
*
* Protocol signature: 2 bytes (0xCA 0xFE)
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

void manager_passive_accept(struct selector_key *key) {
    uint8_t buff[REQUEST_SIZE];
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    ssize_t rcv = recvfrom(key->fd, buff, sizeof(buff), MSG_DONTWAIT, (struct sockaddr *) &client_addr,
                           &client_addr_len);

    uint8_t response_buffer[14];
    memset(response_buffer, 0, 14);
    uint16_t signature = htons(SIGNATURE);
    response_buffer[0] = (signature >> 8) & 0xFF;
    response_buffer[1] = signature & 0xFF;
    response_buffer[2] = VERSION;
    response_buffer[3] = buff[3];
    response_buffer[4] = buff[4];
    if (rcv < 0) {
        response_buffer[5] = UNEXPECTED_ERROR;
        goto send_datagram;
    }
    // chequeo si el signature es correcto
    if (ntohs(signature) != SIGNATURE || rcv != REQUEST_SIZE) {
        response_buffer[5] = INVALID_REQUEST;
        goto send_datagram;
    }
    if (buff[2] != VERSION) {
        response_buffer[5] = INVALID_VERSION;
        goto send_datagram;
    }
    uint8_t password[8];
    memcpy(password, &buff[5], 8);

    if (strncmp((char *) password, (char *) key->data, 8) != 0) {
        response_buffer[5] = UNAUTHORIZED;
        goto send_datagram;
    }

    unsigned char command = buff[13];
    size_t data;
    TStats *stats = malloc(sizeof(TStats));
    getStats(stats);
    switch (command) {
        case 0x00:
            data = stats->historicConnectionQuantity;
            break;
        case 0x01:
            data = stats->currentConnectionQuantity;
            break;
        case 0x02:
            data = stats->bytesSent;
            break;
        case 0x03:
            data = stats->bytesReceived;
            break;
        case 0x04:
            data = stats->bytesSent + stats->bytesReceived;
            break;
        default:
            response_buffer[5] = INVALID_COMMAND;
            goto send_datagram;
    }
    free(stats);
    memcpy(&response_buffer[6], &data, 8);
    send_datagram:

    rcv = sendto(key->fd, response_buffer, RESPONSE_SIZE, 0, (struct sockaddr *) &client_addr, client_addr_len);

    if (rcv < 0) {
        perror("sendto");
    }
}