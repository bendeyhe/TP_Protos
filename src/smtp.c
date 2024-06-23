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
    struct data_parser data_parser;

    /** buffers */
    uint8_t raw_buff_read[2048], raw_buff_write[2048], raw_buff_file[2048]; // TODO: TENEMOS QUE ARREGLAR ESTO!!!
    buffer read_buffer, write_buffer, file_buffer;

    bool go_to_next;
    char mail_from[255];
    char mail_to[255];
    int file_fd;
};

/** maquina de estados general */
enum smtp_state {
    /**
     * escribe el mensaje de bienvenida
     *
     * Intereses:
     *    - OP_WRITE sobre client_fd
     *
     * Transiciones:
     *    - WAITING_EHLO cuando se completa el mensaje
     *    - ERROR        ante cualquier error
     */
    WELCOME,
    /**
     * espera el saludo del cliente (EHLO o HELO)
     *
     * Intereses:
     *    - OP_READ sobre client_fd
     *
     * Transiciones:
     *    - WAITING_EHLO      mientras no se reciba el saludo
     *    - RESPONSE_EHLO     cuando se recibe el saludo
     *    - ERROR             ante cualquier error (IO/parseo)
     */
    WAITING_EHLO,
    /**
     * escribir respuesta del EHLO
     *
     * Intereses:
     *    - OP_WRITE sobre client_fd
     *
     * Transiciones:
     *    - WAITING_MAIL_FROM cuando se completa la respuesta
     *    - ERROR             ante cualquier error
     */
    RESPONSE_EHLO,
    /**
     * espera el 'mail from' del cliente
     *
     * Intereses:
     *    - OP_READ sobre client_fd
     *
     * Transiciones:
     *    - WAITING_MAIL_FROM  mientras no se reciba el 'mail from'
     *    - RESPONSE_MAIL_FROM cuando se recibe el 'mail from'
     *    - ERROR              ante cualquier error (IO/parseo)
     */
    WAITING_MAIL_FROM,
    /**
     * escribir respuesta del MAIL FROM
     *
     * Intereses:
     *    - OP_WRITE sobre client_fd
     *
     * Transiciones:
     *    - WAITING_RCPT_TO cuando se completa la respuesta
     *    - ERROR           ante cualquier error
     */
    RESPONSE_MAIL_FROM,
    /**
     * espera el 'rcpt to' del cliente
     *
     * Intereses:
     *    - OP_READ sobre client_fd
     *
     * Transiciones:
     *    - WAITING_RCPT_TO  mientras no se reciba el 'rcpt to'
     *    - RESPONSE_RCPT_TO cuando se recibe el 'rcpt to'
     *    - ERROR            ante cualquier error (IO/parseo)
     */
    WAITING_RCPT_TO,
    /**
     * escribe la respuesta del RCPT TO
     *
     * Intereses:
     *    - OP_WRITE sobre client_fd
     *
     * Transiciones:
     *    - WAITING_DATA cuando se completa la respuesta
     *    - ERROR        ante cualquier error
     */
    RESPONSE_RCPT_TO,
    /**
     * espera el 'data' del cliente
     *
     * Intereses:
     *    - OP_READ sobre client_fd
     *
     * Transiciones:
     *    - WAITING_DATA cuando se recibe 'rcpt to'
     *    - WAITING_DATA mientras no se reciba el 'data'
     *    - DATA_READ    cuando se recibe el 'data'
     *    - ERROR        ante cualquier error (IO/parseo)
     */
    WAITING_DATA,
    /**
	 * lee la data del cliente.
	 *
	 * Intereses:
	 *     - OP_READ sobre client_fd
	 *
	 */
    DATA_READ,
    /**
	 * escribe la data del cliente.
	 *
	 * Intereses:
     *     - NOP      sobre client_fd
	 *     - OP_WRITE sobre archivo_fd
	 *
     * Transiciones:
     *   - DATA_WRITE  mientras tenga cosas para escribir
     *   - DATA_READ   cuando se me vació el buffer
     *   - ERROR       ante cualquier error (IO/parseo)
	 */
    DATA_WRITE,
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

static void save_response(struct smtp *state, char *message) {
    size_t count;
    uint8_t *ptr;
    ptr = buffer_write_ptr(&state->write_buffer, &count);

    strcpy((char *) ptr, message);
    buffer_write_adv(&state->write_buffer, strlen(message));
}

static bool request_process(struct smtp *state, unsigned current_state) {
    switch (current_state) {
        case WAITING_EHLO:
            if (strcasecmp(state->request_parser.request->verb, "EHLO") == 0 ||
                strcasecmp(state->request_parser.request->verb, "HELO") == 0) {
                save_response(state, "250 server at your service\n");
                state->go_to_next = true;
            } else {
                save_response(state, "EHLO/HELO first is expected!\r\n");
            }
            break;
        case WAITING_MAIL_FROM:
            if (strcasecmp(state->request_parser.request->verb, "MAIL FROM") == 0) {
                // TODO hacer que si no hay arg1 tire 'Syntax error'
                strcpy(state->mail_from, state->request_parser.request->arg1);
                save_response(state,
                              "250 OK - MAIL FROM: <mail_from>\r\n"); // TODO borrar despues el - MAIL FROM: <mail_from>
                state->go_to_next = true;
            } else {
                save_response(state, "Bad sequence of commands! MAIL FROM: is expected\r\n");
            }
            break;
        case WAITING_RCPT_TO:
            if (strcasecmp(state->request_parser.request->verb, "RCPT TO") == 0) {
                // TODO hacer que si no hay arg1 tire 'Syntax error'
                strcpy(state->mail_to, state->request_parser.request->arg1);
                save_response(state, "250 OK - RCPT TO: <mail_to>\r\n"); // TODO borrar despues el - RCPT TO: <mail_to>
                state->go_to_next = true;
            } else {
                save_response(state, "Bad sequence of commands! RCPT TO: is expected\r\n");
            }
            break;
        case WAITING_DATA:
            if (strcasecmp(state->request_parser.request->verb, "DATA") == 0) {
                save_response(state, "354 Start mail input; end with <CRLF>.<CRLF>\r\n");
                state->go_to_next = true;
            } else if (strcasecmp(state->request_parser.request->verb, "RCPT TO") == 0) {
                // TODO hacer que si no hay arg1 tire 'Syntax error'
                strcpy(state->mail_to, state->request_parser.request->arg1);
                save_response(state, "250 OK - RCPT TO: <mail_to>\r\n"); // TODO borrar despues el - RCPT TO
            } else {
                save_response(state, "Bad sequence of commands! DATA is expected\r\n");
            }
            break;
        default:
            return false;
            break;
    }
    return true;
}

static unsigned
request_read2(struct selector_key *key, struct smtp *state, unsigned current_state, unsigned next_state) {
    bool error = false;

    int st = request_consume(&state->read_buffer, &state->request_parser, &error);
    if (request_is_done(st, 0)) {
        if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_WRITE)) {
            if(request_process(state, current_state))
                return next_state;
            else
                return ERROR;
        } else {
            return ERROR;
        }
    }
    return current_state;
}

static unsigned request_read(struct selector_key *key, unsigned current_state, unsigned next_state) {
    struct smtp *state = ATTACHMENT(key);
    state->go_to_next = false;

    if (buffer_can_read(&state->read_buffer)) {
        return request_read2(key, state, current_state, next_state);
    } else {
        size_t count;
        uint8_t *ptr = buffer_write_ptr(&state->read_buffer, &count);
        ssize_t n = recv(key->fd, ptr, count, 0);

        if (n > 0) {
            buffer_write_adv(&state->read_buffer, n);
            return request_read2(key, state, current_state, next_state);
        } else {
            return false;
        }
    }
}

static unsigned int data_read2(struct selector_key *key, struct smtp *state) {
    return ERROR;
    /*
    unsigned int ret = DATA_READ;
    bool error = false;

    buffer *rb = &state->read_buffer;
    buffer *wb = &state->file_buffer;

    while (buffer_can_read(rb)) {
        const uint8_t c = buffer_read(rb);
        st = data_parser_feed(&state->data_parser, c);
        if (data_is_done(st, &error)) {
            break;
        }
    }

    struct selector_key *file_key = malloc(sizeof(struct selector_key));

    if (data_is_done(st, &error)) {
        if (SELECTOR_SUCCESS != selector_register(key->s, state->file_fd, &smtp_handler, OP_WRITE, state)) {
            return ERROR;
        }
        if (SELECTOR_SUCCESS != selector_set_interest_key(file_key, OP_NOOP)) {
            return ERROR;
        }
        return DATA_WRITE;
    } else if (error) {
        return ERROR;
    } else {
        return DATA_READ;
    }
     */
}

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

static unsigned response_write(struct selector_key *key, unsigned current_state, unsigned next_state) {
    unsigned ret = current_state;

    size_t count;
    buffer *wb = &ATTACHMENT(key)->write_buffer;

    uint8_t *ptr = buffer_read_ptr(wb, &count);
    ssize_t n = send(key->fd, ptr, count, MSG_NOSIGNAL);

    if (n >= 0) {
        buffer_read_adv(wb, n);
        if (!buffer_can_read(wb)) {
            if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_READ))
                ret = next_state;
            else
                ret = ERROR;
        }
    } else {
        ret = ERROR;
    }

    return ret;
}

static unsigned data_write(struct selector_key *key) {
    return ERROR;
}

static unsigned waiting_ehlo(struct selector_key *key) {
    return request_read(key, WAITING_EHLO, RESPONSE_EHLO);
}

static unsigned waiting_mail_from(struct selector_key *key) {
    return request_read(key, WAITING_MAIL_FROM, RESPONSE_MAIL_FROM);
}

static unsigned waiting_rcpt_to(struct selector_key *key) {
    return request_read(key, WAITING_RCPT_TO, RESPONSE_RCPT_TO);
}

static unsigned waiting_data(struct selector_key *key) {
    return request_read(key, WAITING_DATA, DATA_READ);
}

static unsigned welcome(struct selector_key *key) {
    return response_write(key, WELCOME, WAITING_EHLO);
}

static unsigned response_ehlo(struct selector_key *key) {
    if (response_write(key, RESPONSE_EHLO, WAITING_MAIL_FROM) == WAITING_MAIL_FROM
        && ATTACHMENT(key)->go_to_next)
        return WAITING_MAIL_FROM;
    return WAITING_EHLO;
}

static unsigned response_mail_from(struct selector_key *key) {
    if (response_write(key, RESPONSE_MAIL_FROM, WAITING_RCPT_TO) == WAITING_RCPT_TO
        && ATTACHMENT(key)->go_to_next)
        return WAITING_RCPT_TO;
    return WAITING_MAIL_FROM;
}

static unsigned response_rcpt_to(struct selector_key *key) {
    if (response_write(key, RESPONSE_RCPT_TO, WAITING_DATA) == WAITING_DATA
        && ATTACHMENT(key)->go_to_next)
        return WAITING_DATA;
    return WAITING_RCPT_TO;
}

/** definición de handlers para cada estado */
static const struct state_definition client_statbl[] = {
        {
                .state            = WELCOME,
                .on_write_ready   = welcome,
        },
        {
                .state            = WAITING_EHLO,
                .on_arrival       = request_read_init,
                .on_departure     = request_read_close,
                .on_read_ready    = waiting_ehlo,
        },
        {
                .state            = RESPONSE_EHLO,
                .on_write_ready   = response_ehlo,
        },
        {
                .state            = WAITING_MAIL_FROM,
                .on_arrival       = request_read_init,
                .on_read_ready    = waiting_mail_from,
        },
        {
                .state            = RESPONSE_MAIL_FROM,
                .on_write_ready   = response_mail_from,
        },
        {
                .state            = WAITING_RCPT_TO,
                .on_arrival       = request_read_init,
                .on_read_ready    = waiting_rcpt_to,
        },
        {
                .state            = RESPONSE_RCPT_TO,
                .on_write_ready   = response_rcpt_to,
        },
        {
                .state            = WAITING_DATA,
                .on_arrival       = request_read_init,
                .on_read_ready    = waiting_data,
        },
        {
                .state            = DATA_READ,
                .on_arrival       = request_read_init,
                .on_read_ready    = data_read,
        },
        {
                .state            = DATA_WRITE,
                .on_write_ready   = data_write,
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

static void smtp_read(struct selector_key *key) {
    struct state_machine *stm = &ATTACHMENT(key)->stm;
    const enum smtp_state st = stm_handler_read(stm, key);

    if (ERROR == st || DONE == st) {
        smtp_done(key);
    }
}

static void smtp_write(struct selector_key *key) {
    struct state_machine *stm = &ATTACHMENT(key)->stm;
    const enum smtp_state st = stm_handler_write(stm, key);

    if (ERROR == st || DONE == st) { // si hubo un error, cierro la conexión
        smtp_done(key);
    } else if (WAITING_EHLO == st || WAITING_MAIL_FROM == st || WAITING_RCPT_TO == st || WAITING_DATA == st ||
               DATA_READ == st) {
        buffer *rb = &ATTACHMENT(key)->read_buffer;
        if (buffer_can_read(rb)) {
            smtp_read(key); // si hay para leer en el buffer sigo leyendo sin quedarme bloqueado
        }
    }
}

static void smtp_done(struct selector_key *key) {
    if (key->fd != -1) {
        if (SELECTOR_SUCCESS != selector_unregister_fd(key->s, key->fd)) {
            abort();
        }
        close(key->fd);
    }
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

static void smtp_close(struct selector_key *key) {
    /*
    socks5_destroy(ATTACHMENT(key));
     */
    smtp_destroy(ATTACHMENT(key));
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

    state->stm.initial = WELCOME;
    state->stm.max_state = ERROR;
    state->stm.states = client_statbl;
    stm_init(&state->stm);

    buffer_init(&state->read_buffer, N(state->raw_buff_read), state->raw_buff_read);
    buffer_init(&state->write_buffer, N(state->raw_buff_write), state->raw_buff_write);

    char *message = "220 Service Ready\n";
    uint8_t len = strlen(message);

    memcpy(&state->raw_buff_write, message, len);
    buffer_write_adv(&state->write_buffer, len);

    state->request_parser.request = &state->request;
    request_parser_init(&state->request_parser);

    data_parser_init(&state->data_parser);

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
