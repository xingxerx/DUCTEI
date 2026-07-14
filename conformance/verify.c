/* Feeds the Rust-emitted stream one byte at a time into Qallow's real
 * incremental decoder. Exit 0 iff all five frames decode in order and
 * the envelope key/blob are recovered intact. */
#include <qallow/sync_wire.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    if (argc < 2) return 2;
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 2;
    static uint8_t buf[1 << 20];
    size_t n = fread(buf, 1, sizeof buf, f);
    fclose(f);
    int expect[5] = {QSW_F_HELLO, QSW_F_HELLO_ACK, QSW_F_ENVELOPE, QSW_F_BATCH_END, QSW_F_BYE};
    size_t off = 0, fi = 0, win = 0;
    while (fi < 5 && off + win <= n) {
        qsw_frame fr; size_t used = 0;
        qsw_status st = qsw_decode(buf + off, win, &fr, &used);
        if (st == QSW_NEED_MORE) { win++; continue; }
        if (st != QSW_OK) { fprintf(stderr, "decode err %d at frame %zu\n", st, fi); return 1; }
        if (fr.type != expect[fi]) { fprintf(stderr, "type mismatch\n"); return 1; }
        if (fr.type == QSW_F_ENVELOPE) {
            if (fr.u.env.lamport != 42) return 1;
            if (memcmp(fr.u.env.key, "qallow.semantic.cert|limen.cert.j1", fr.u.env.key_len) != 0) return 1;
            if (memcmp(fr.u.env.blob, "{\"tier\":2}", fr.u.env.blob_len) != 0) return 1;
        }
        if (fr.type == QSW_F_HELLO && qsw_hello_validate(&fr.u.hello) != QSW_OK) return 1;
        off += used; win = 0; fi++;
    }
    if (fi != 5) { fprintf(stderr, "only %zu frames\n", fi); return 1; }
    puts("CONFORMANCE PASS");
    return 0;
}
