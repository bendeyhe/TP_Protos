#include "manager.h"
#include "../../lib/headers/selector.h"
#include "../../lib/headers/stm.h"
#include <sys/socket.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

char buff[1024];

void manager_passive_accept(struct selector_key *key) {
    // voy a aceptar la conexion
    // armar el datagrama con la informacion del cliente
    // y enviarlo al selector para que lo maneje


    struct sockaddr_storage client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    ssize_t rcv = recvfrom(key->fd, buff, sizeof(buff) - 1, 0, (struct sockaddr *) &client_addr, &client_addr_len);

    if (rcv < 0) {
        perror("recvfrom");
        return;
    }

    buff[rcv] = 0;

    //printf("Recibido: %s\n", datagram);

    switch (buff[0]) {
        case 'h':
            break;
    }
}