#ifndef TP_PROTOS_SMTP_H
#define TP_PROTOS_SMTP_H

#include "lib/headers/selector.h"

void smtp_passive_accept(struct selector_key *key);

void init_transformations(char *program);

#endif //TP_PROTOS_SMTP_H
