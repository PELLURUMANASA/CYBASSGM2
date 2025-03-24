#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Include your function here
void tls1_process_heartbeat(SSL *ssl, const unsigned char *data, int len) {
    unsigned short hb_len;
    unsigned char *payload;
    if (len < 3) return;
    hb_len = (data[1] << 8) | data[2]; // Read 16-bit length
    payload = (unsigned char *)malloc(hb_len); // Potential over-read
    if (!payload) return;
    memcpy(payload, data + 3, hb_len); // Unsafe copy
    printf("Heartbeat processed, %d bytes read\n", hb_len);
    free(payload);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Here we pass the fuzzer input directly to the TLS function
    tls1_process_heartbeat(NULL, data, size);
    return 0;
}
