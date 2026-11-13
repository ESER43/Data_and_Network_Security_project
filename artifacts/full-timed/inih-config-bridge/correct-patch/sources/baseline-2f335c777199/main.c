#include <stdio.h>
#include <string.h>

#include "ini.h"

struct settings {
    char stored_value[32];
};

static int on_value(void *user, const char *section, const char *name, const char *value)
{
    struct settings *settings = (struct settings *)user;

    if (section == NULL || strcmp(section, "storage") != 0 ||
        name == NULL || (strcmp(name, "path") != 0 && strcmp(name, "mirror") != 0)) {
        return 1;
    }

    /* Vulnerability: the INI value is controlled by the input stream. */
    strcpy(settings->stored_value, value);
    return 1;
}

int main(void)
{
    char input[4096];
    struct settings settings = {{0}};
    size_t length = fread(input, 1, sizeof(input) - 1, stdin);
    input[length] = '\0';

    if (ini_parse_string(input, on_value, &settings) != 0) {
        return 2;
    }
    printf("OK:%s\n", settings.stored_value);
    return 0;
}
