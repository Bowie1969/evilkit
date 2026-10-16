/* Probe payload for the EvilKit malware-scripting MCP live proof.
 *
 * Stands in for a generated implant, and does the two things the chain has to
 * show to be provable: announce itself on the host it actually runs on, and
 * leave a beacon file that can be read back over a *separate* session (so
 * "it ran" is not the same claim as "the deployer said it ran").
 *
 * Build:  gcc -o /tmp/evilkit_probe probe_payload.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char **argv) {
    char host[256] = "unknown";
    gethostname(host, sizeof(host) - 1);

    const char *beacon = getenv("EVILKIT_PROOF_BEACON");
    if (!beacon) beacon = "/tmp/evilkit_proof.beacon";

    FILE *fh = fopen(beacon, "a");
    if (fh) {
        fprintf(fh, "pid=%d uid=%d host=%s t=%ld argv0=%s\n",
                (int)getpid(), (int)getuid(), host, (long)time(NULL), argv[0]);
        fclose(fh);
    }

    printf("evilkit-probe running: host=%s pid=%d uid=%d\n",
           host, (int)getpid(), (int)getuid());
    if (argc > 1 && strcmp(argv[1], "--help") == 0) {
        printf("usage: %s [--background]\n", argv[0]);
    }
    return 0;
}
