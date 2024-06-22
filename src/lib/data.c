/**
 * data.c -- parser del data de SOCKS5
 */
#include <string.h> // memset
#include <arpa/inet.h>

#include "headers/data.h"

static void
remaining_set(struct data_parser *p) {
    //p->i = 0;
}

//static int
//remaining_is_done(struct data_parser* p) {
//    return p->i >= p->n;
//}

//////////////////////////////////////////////////////////////////////////////

static enum data_state
verb(const uint8_t c, struct data_parser *p) {
    enum data_state next;
    switch (c) {
        case '\r':
            next = data_cr;
            break;
        default:
            next = data_verb;
    }
    if (next == data_verb) {
        if (p->i < sizeof(p->data->verb) - 1) // TODO chequear esto
            p->data->verb[p->i++] = (char) c;
    } else {
        p->data->verb[p->i] = 0;
        //if (strcmp(p->data->verb, "data") == 0)
        //next = data_data;
    }
    return next;
}

static enum data_state
write(const uint8_t c, struct data_parser *p) {
    return data_arg1;
}

extern void
data_parser_init(struct data_parser *p) {
    p->state = data_verb;
    memset(p->data, 0, sizeof(*(p->data)));
}


extern enum data_state
data_parser_feed(struct data_parser *p, const uint8_t c) {
    enum data_state next;

    switch (p->state) {
        case data_data:
            next = verb(c, p);
            break;
        case data_cr:
            next = separator_arg1(c, p);
            break;
        case data_crlf:
            next = arg1(c, p);
            break;
        case data_crlfdot:
            switch (c) {
                case '\n':
                    next = data_done;
                    break;
                default:
                    next = data_verb;
                    break;
            }
            break;
        case data_crlfdotcr:
        case data_done:
        default:
            next = data_error;
            break;
    }

    return p->state = next;
}

extern bool
data_is_done(const enum data_state st, bool *errored) {
    if (st >= data_error && errored != 0) {
        *errored = true;
    }
    return st >= data_done;
}

extern enum data_state
data_consume(buffer *b, struct data_parser *p, bool *errored) {
    enum data_state st = p->state;

    while (buffer_can_read(b)) {
        const uint8_t c = buffer_read(b);
        st = data_parser_feed(p, c);
        if (data_is_done(st, errored)) {
            break;
        }
    }
    return st;
}

extern void
data_close(struct data_parser *p) {
    // nada que hacer
}
