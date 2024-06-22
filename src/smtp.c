#include "smtp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include "lib/headers/buffer.h"
#include "lib/headers/stm.h"
#include "lib/headers/request.h"
#include <strings.h>
#include "lib/headers/data.h"

#define N(x) (sizeof(x)/sizeof(x[0]))

/** obtiene el struct (smtp *) desde la llave de selección **/
#define ATTACHMENT(key) ((struct smtp *)(key)->data)

struct smtp {
    /** información del cliente */
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len;

    /** maquinas de estados */
    struct state_machine stm;

    /** parsers */
    struct request request;
    struct request_parser request_parser;

    /** buffers */
    uint8_t raw_buff_read[2048], raw_buff_write[2048]; // TODO: TENEMOS QUE ARREGLAR ESTO!!!
    buffer read_buffer, write_buffer;
    //bool is_data = false;
    char mail_from[255];
};

/** maquina de estados general */
enum smtp_state {
    /**
     * recibe el mensaje `hello` del cliente, y lo procesa
     *
     * Intereses:
     *     - OP_READ sobre client_fd
     *
     * Transiciones:
     *   - HELLO_READ  mientras el mensaje no esté completo
     *   - HELLO_WRITE cuando está completo
     *   - ERROR       ante cualquier error (IO/parseo)
     */
    RESPONSE_WRITE,
    /**
     * envía la respuesta del `hello' al cliente.
     *
     * Intereses:
     *     - OP_WRITE sobre client_fd
     *
     * Transiciones:
     *   - HELLO_WRITE  mientras queden bytes por enviar
     *   - REQUEST_READ cuando se enviaron todos los bytes
     *   - ERROR        ante cualquier error (IO/parseo)
     */
    REQUEST_READ,

    /**
	 * lee la data del cliente.
	 *
	 * Intereses:
	 *     - OP_READ sobre client_fd
	 *
	 */
    DATA_READ,

    // estados terminales
    DONE,
    ERROR,
};

static void smtp_done(struct selector_key *key);

static void request_read_init(const unsigned s, struct selector_key *key) {
    struct request_parser *p = &ATTACHMENT(key)->request_parser;
    p->request = &ATTACHMENT(key)->request;
    request_parser_init(p);
}

static void request_read_close(const unsigned state, struct selector_key *key) {
    request_close(&ATTACHMENT(key)->request_parser);
}

static enum smtp_state request_process(struct smtp *state) {
    if (strcasecmp(state->request_parser.request->verb, "data") == 0) {
        //state->is_data = true;
        return RESPONSE_WRITE;
    }
    if (strcasecmp(state->request_parser.request->verb, "mail from") == 0) {
        // TODO chequear si hay arg1
        strcpy(state->mail_from, state->request_parser.request->arg1);
        // generar la respuesta
        size_t count;
        uint8_t *ptr;
        ptr = buffer_write_ptr(&state->write_buffer, &count);

        strcpy((char *) ptr, "251 Ok\r\n");
        buffer_write_adv(&state->write_buffer, 8);

        return RESPONSE_WRITE;
    }
    if (strcasecmp(state->request_parser.request->verb, "ehlo") == 0) {
        //
        // 250-username
        // 250-PIPELINING
        // 250 SIZE 111111
        return RESPONSE_WRITE;
    }
    //502 Error: command not recognized se puede tirar cuando no es un comando reconocido

    // TODO lo de aca abajo es momentaneo, en un futuro dejar return ERROR nada mas
    size_t count;
    uint8_t *ptr;

    ptr = buffer_write_ptr(&state->write_buffer, &count);

    strcpy((char *) ptr, "250 Ok\r\n");
    buffer_write_adv(&state->write_buffer, 8);
    return RESPONSE_WRITE;
}

static unsigned int request_read2(struct selector_key *key, struct smtp *state) {
    unsigned int ret = REQUEST_READ;
    bool error = false;
    int st = request_consume(&state->read_buffer, &state->request_parser, &error);
    if (request_is_done(st, 0)) {
        //Procesamiento
        //request_read_process

        if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_WRITE)) {
            ret = request_process(state); // tengo todo completo
        } else {
            ret = ERROR;
        }
    }
    return ret;
}

/** lee todos los bytes del mensaje de tipo `hello' y inicia su proceso */
static unsigned request_read(struct selector_key *key) {
    unsigned ret;
    struct smtp *state = ATTACHMENT(key);

    if (buffer_can_read(&state->read_buffer)) {
        ret = request_read2(key, state);
    } else {
        size_t count;
        uint8_t *ptr = buffer_write_ptr(&state->read_buffer, &count);
        ssize_t n = recv(key->fd, ptr, count, 0);

        if (n > 0) {
            buffer_write_adv(&state->read_buffer, n);
            ret = request_read2(key, state);
        } else {
            ret = ERROR;
        }
    }
    return ret;
}

/*
static unsigned int data_read2(struct selector_key *key, struct smtp *state) {
    unsigned int ret = DATA_READ;
    bool error = false;

    enum data_state st = p->state;

    while (buffer_can_read(b)) {
        const uint8_t c = buffer_read(b);
        st = data_parser_feed(p, c);
        if (data_is_done(st, errored)) {
            break;
        }
    }

    if (data_is_done(st, 0)) {
        //Procesamiento
        //request_read_process

        if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_WRITE)) {
            ret = request_process(state); // tengo todo completo
        } else {
            ret = ERROR;
        }
    }
    return ret;
}
*/

/*
static unsigned data_read(struct selector_key *key) {
    unsigned ret;
    struct smtp *state = ATTACHMENT(key);

    if (buffer_can_read(&state->read_buffer)) {
        ret = data_read2(key, state);
    } else {
        size_t count;
        uint8_t *ptr = buffer_write_ptr(&state->read_buffer, &count);
        ssize_t n = recv(key->fd, ptr, count, 0);

        if (n > 0) {
            buffer_write_adv(&state->read_buffer, n);
            ret = data_read2(key, state);
        } else {
            ret = ERROR;
        }
    }
    return ret;
}
*/

static unsigned response_write(struct selector_key *key) {
    unsigned ret = RESPONSE_WRITE;
    bool error = false;

    size_t count;
    buffer *wb = &ATTACHMENT(key)->write_buffer;

    uint8_t *ptr = buffer_read_ptr(wb, &count);
    ssize_t n = send(key->fd, ptr, count, MSG_NOSIGNAL);

    if (n >= 0) {
        buffer_read_adv(wb, n);
        if (!buffer_can_read(wb)) {
            // TODO ver si voy para dara o request
            if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_READ)) {
                ret = REQUEST_READ;
                //ret = &ATTACHMENT(key)->is_data ? DATA_READ : REQUEST_READ;
                // TODO: Chequear si hay que cambiar a DATA_READ
            } else {
                ret = ERROR;
            }
        }
    } else {
        ret = ERROR;
    }

    return error ? ERROR : ret;
}

/** definición de handlers para cada estado */
static const struct state_definition client_statbl[] = {
        {
                .state            = RESPONSE_WRITE,/*
                .on_arrival       = hello_read_init,
                .on_departure     = hello_read_close,*/
                .on_write_ready    = response_write,
        },
        {
                .state            = REQUEST_READ,
                .on_arrival       = request_read_init,
                .on_departure     = request_read_close,
                .on_read_ready    = request_read,
        },
        {
                .state = DATA_READ,
                //.on_arrival       = request_read_init, // TODO AGREGAR INIT
                //.on_departure     = request_read_close,
                //.on_read_ready    = data_read,
        },
        {
                .state = DONE,
        },
        {
                .state = ERROR,
        },
};

/* declaración forward de los handlers de selección de una conexión
 * establecida entre un cliente y el proxy.
 */
static void smtp_read(struct selector_key *key);

static void smtp_write(struct selector_key *key);

static void smtp_close(struct selector_key *key);

static const struct fd_handler smtp_handler = {
        .handle_read   = smtp_read,
        .handle_write  = smtp_write,
        .handle_close  = smtp_close,
};

///////////////////////////////////////////////////////////////////////////////
// Handlers top level de la conexión pasiva.
// son los que emiten los eventos a la maquina de estados.

static void
smtp_read(struct selector_key *key) {
    struct state_machine *stm = &ATTACHMENT(key)->stm;
    const enum smtp_state st = stm_handler_read(stm, key);

    if (ERROR == st || DONE == st) {
        smtp_done(key);
    }
}

static void
smtp_write(struct selector_key *key) {
    struct state_machine *stm = &ATTACHMENT(key)->stm;
    const enum smtp_state st = stm_handler_write(stm, key);

    if (ERROR == st || DONE == st) {
        smtp_done(key);
    } else if (REQUEST_READ == st || DATA_READ == st) {
        buffer *rb = &ATTACHMENT(key)->read_buffer;
        if (buffer_can_read(rb)) {
            smtp_read(key); // si hay para leer en el buffer sigo leyendo sin quedarme bloqueado
        }
    }
}

static void
smtp_close(struct selector_key *key) {
    /*
    socks5_destroy(ATTACHMENT(key));
     */
}

static void
smtp_done(struct selector_key *key) {
    /*
    const int fds[] = {
            ATTACHMENT(key)->client_fd,
            ATTACHMENT(key)->origin_fd,
    };
    for(unsigned i = 0; i < N(fds); i++) {
        if(fds[i] != -1) {
            if(SELECTOR_SUCCESS != selector_unregister_fd(key->s, fds[i])) {
                abort();
            }
            close(fds[i]);
        }
    }
     */
}

static void smtp_destroy(struct smtp *state) {
    free(state);
}

/** Intenta aceptar la nueva conexión entrante*/
void smtp_passive_accept(struct selector_key *key) {
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    struct smtp *state = NULL;

    const int client = accept(key->fd, (struct sockaddr *) &client_addr, &client_addr_len);
    if (client == -1) {
        goto fail;
    }
    if (selector_fd_set_nio(client) == -1) {
        goto fail;
    }
    state = malloc(sizeof(struct smtp));
    if (state == NULL) {
        // sin un estado, nos es imposible manejaro.
        // tal vez deberiamos apagar accept() hasta que detectemos
        // que se liberó alguna conexión.
        goto fail;
    }
    memset(state, 0, sizeof(*state));
    memcpy(&state->client_addr, &client_addr, client_addr_len);
    state->client_addr_len = client_addr_len;

    state->stm.initial = RESPONSE_WRITE;
    state->stm.max_state = ERROR;
    state->stm.states = client_statbl;
    stm_init(&state->stm);

    buffer_init(&state->read_buffer, N(state->raw_buff_read), state->raw_buff_read);
    buffer_init(&state->write_buffer, N(state->raw_buff_write), state->raw_buff_write);

    memcpy(&state->raw_buff_write, "Hello! Identify yourself\n", 26);
    buffer_write_adv(&state->write_buffer, 26);

    state->request_parser.request = &state->request;
    request_parser_init(&state->request_parser);

    if (SELECTOR_SUCCESS != selector_register(key->s, client, &smtp_handler, OP_WRITE, state)) {
        goto fail;
    }
    return;
    fail:
    if (client != -1) {
        close(client);
    }
    smtp_destroy(state);
}
