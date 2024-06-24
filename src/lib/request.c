#include <string.h> // memset
#include <arpa/inet.h>
#include <stdbool.h>
#include "headers/request.h"
#include <strings.h>
#include <stdio.h>

static void remaining_set(struct request_parser *p) {
    p->i = 0;
}

static enum request_state verb(const uint8_t c, struct request_parser *p) {
    enum request_state next;
    switch (c) {
        case '\r':
            next = request_cr;
            break;
        case ' ':
            if (p->i == 4 && (strcasecmp(p->request->verb, "MAIL") == 0 ||
                              strcasecmp(p->request->verb, "RCPT") == 0))
                next = request_verb;
            else
                next = request_arg1;
            break;
        case ':':
            next = request_arg1;
            break;
        default:
            next = request_verb;
    }
    if (next == request_verb) {
        if (p->i < sizeof(p->request->verb) - 1)
            p->request->verb[p->i++] = (char) c;
    } else {
        p->request->verb[p->i] = 0;
        remaining_set(p);
    }
    return next;
}

static enum request_state arg1(const uint8_t c, struct request_parser *p) {
    enum request_state next;
    switch (c) {
        case '\r':
            next = request_cr;
            break;
        default:
            next = request_arg1;
    }
    if (next == request_arg1) {
        if (p->i < sizeof(p->request->arg1) - 1)
            p->request->arg1[p->i++] = (char) c;
    } else {
        p->request->arg1[p->i] = 0;
        remaining_set(p);
    }
    return next;
}

extern void request_parser_init(struct request_parser *p) {
    p->state = request_verb;
    memset(p->request, 0, sizeof(*(p->request)));
    p->i = 0;
}

extern enum request_state request_parser_feed(struct request_parser *p, const uint8_t c) {
    enum request_state next;

    switch (p->state) {
        case request_verb:
            next = verb(c, p);
            break;
        case request_arg1:
            next = arg1(c, p);
            break;
        case request_cr:
            switch (c) {
                case '\n':
                    next = request_done;
                    break;
                default:
                    next = request_error;
                    break;
            }
            break;
        case request_done:
        case request_error:
            next = p->state;
            break;
        default:
            next = request_error;
            break;
    }

    return p->state = next;
}

extern bool request_is_done(const enum request_state st, bool *errored) {
    if (st >= request_error && errored != 0) {
        *errored = true;
    }
    return st >= request_done;
}

extern enum request_state request_consume(buffer *b, struct request_parser *p, bool *errored) {
    enum request_state st = p->state;

    while (buffer_can_read(b)) {
        const uint8_t c = buffer_read(b);
        st = request_parser_feed(p, c);
        if (request_is_done(st, errored)) {
            break;
        }
    }
    return st;
}

extern void
request_close(struct request_parser *p) {
    // nada que hacer
}
