/**
 * data.c -- parser del data de SOCKS5
 */
#include <string.h> // memset
#include <arpa/inet.h>
#include <stdio.h>

#include "headers/data.h"

#define N(x) (sizeof(x)/sizeof((x)[0]))

static enum data_state data(const uint8_t c, struct data_parser *p) {
    enum data_state next;
    switch (c) {
        case '\r':
            next = data_cr;
            break;
        default:
            next = data_data;
            buffer_write(&p->output_buffer, c);
            break;
    }
    return next;
}

static enum data_state d_cr(const uint8_t c, struct data_parser *p) {
    enum data_state next;
    switch (c) {
        case '\n':
            next = data_crlf;
            break;
        default:
            next = data_data;
            buffer_write(&p->output_buffer, '\r');
            buffer_write(&p->output_buffer, c);
            break;
    }
    return next;
}

static enum data_state d_crlf(const uint8_t c, struct data_parser *p) {
    enum data_state next;
    switch (c) {
        case '.':
            next = data_crlfdot;
            break;
        default:
            next = data_data;
            buffer_write(&p->output_buffer, '\r');
            buffer_write(&p->output_buffer, '\n');
            buffer_write(&p->output_buffer, c);
            break;
    }
    return next;
}

static enum data_state d_crlfdot(const uint8_t c, struct data_parser *p) {
    enum data_state next;
    switch (c) {
        case '\r':
            next = data_crlfdotcr;
            break;
        default:
            next = data_data;
            buffer_write(&p->output_buffer, '\r');
            buffer_write(&p->output_buffer, '\n');
            buffer_write(&p->output_buffer, '.');
            buffer_write(&p->output_buffer, c);
            break;
    }
    return next;
}

static enum data_state d_crlfdotcr(const uint8_t c, struct data_parser *p) {
    enum data_state next;
    switch (c) {
        case '\n':
            next = data_done;
            break;
        default:
            next = data_data;
            buffer_write(&p->output_buffer, '\r');
            buffer_write(&p->output_buffer, '\n');
            buffer_write(&p->output_buffer, '.');
            buffer_write(&p->output_buffer, '\r');
            buffer_write(&p->output_buffer, c);
            break;
    }
    return next;
}

extern void data_parser_init(struct data_parser *p) {
    buffer_init(&p->output_buffer, N(p->bytes), p->bytes);
    p->state = data_crlf;
}

extern enum data_state data_parser_feed(struct data_parser *p, const uint8_t c) {
    enum data_state next;

    switch (p->state) {
        case data_data:
            next = data(c, p);
            break;
        case data_cr:
            next = d_cr(c, p);
            break;
        case data_crlf:
            next = d_crlf(c, p);
            break;
        case data_crlfdot:
            next = d_crlfdot(c, p);
            break;
        case data_crlfdotcr:
            next = d_crlfdotcr(c, p);
            break;
        case data_done:
        default:
            next = data_done;
            break;
    }

    return p->state = next;
}

extern bool data_is_done(const enum data_state st) {
    return st >= data_done;
}

extern enum data_state data_consume(buffer *b, struct data_parser *p, bool *errored) {
    enum data_state st = p->state;

    while (buffer_can_read(b)) {
        const uint8_t c = buffer_read(b);
        st = data_parser_feed(p, c);
        if (data_is_done(st)) {
            break;
        }
    }
    return st;
}

extern void data_close(struct data_parser *p) {
    // nada que hacer
}
