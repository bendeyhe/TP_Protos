#include "headers/stats.h"
#include <string.h>

static TStats stats;

void statsInit() {
    memset(&stats, 0, sizeof(TStats));
}

void newUserConnection() {
    stats.historicConnectionQuantity++;
    stats.currentConnectionQuantity++;
}

void userDisconnection() {
    stats.currentConnectionQuantity--;
}

void bytesSent(size_t bytes) {
    stats.bytesSent += bytes;
}

void bytesReceived(size_t bytes) {
    stats.bytesReceived += bytes;
}

void getStats(TStats *stats2) {
    stats2->historicConnectionQuantity = stats.historicConnectionQuantity;
    stats2->currentConnectionQuantity = stats.currentConnectionQuantity;
    stats2->bytesSent = stats.bytesSent;
    stats2->bytesReceived = stats.bytesReceived;
}