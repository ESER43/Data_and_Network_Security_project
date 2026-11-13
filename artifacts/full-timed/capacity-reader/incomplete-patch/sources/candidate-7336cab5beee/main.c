#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    char size_text[128];
    char payload[256];
    char *end = NULL;

    if (fgets(size_text, sizeof(size_text), stdin) == NULL ||
        fgets(payload, sizeof(payload), stdin) == NULL) {
        return 2;
    }
    size_text[strcspn(size_text, "\r\n")] = '\0';
    payload[strcspn(payload, "\r\n")] = '\0';

    errno = 0;
    unsigned long long parsed = strtoull(size_text, &end, 10);
    if (errno == ERANGE || end == size_text || *end != '\0' || parsed > SIZE_MAX) {
        return 2;
    }
    size_t requested = (size_t)parsed;

    /* Incomplete fix: this still permits values that wrap when adding 16. */
    if (requested > SIZE_MAX - 8) {
        return 2;
    }
    size_t allocation_size = requested + 16;
    char *buffer = (char *)malloc(allocation_size);
    if (buffer == NULL) {
        return 3;
    }

    size_t payload_length = strlen(payload);
    memcpy(buffer, payload, payload_length + 1);
    printf("OK:%s\n", buffer);
    free(buffer);
    return 0;
}
