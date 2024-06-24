#ifndef STATS_H
#define STATS_H

#include <stdlib.h>

typedef struct {
    //suma de todas las conexiones desde siempre
    size_t historicConnectionQuantity;

    //cantidad de conexiones actuales
    size_t currentConnectionQuantity;

    //cantidad de bytes enviados por el servidor
    size_t bytesSent;

    //cantidad de bytes recibidos por el servidor
    size_t bytesReceived;
} TStats;

void statsInit();

void newUserConnection();

void userDisconnection();

void bytesSent(size_t bytes);

void bytesReceived(size_t bytes);

void getStats(TStats *stats);

#endif