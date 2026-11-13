#include <stdio.h>
#include <string.h>

#include "cJSON.h"

int main(void)
{
    char input[1024];
    char *separator;
    char *initial_value;
    char *replacement_text;
    const char *replacement;
    cJSON *item;
    char *result;

    if (fgets(input, sizeof(input), stdin) == NULL) {
        return 2;
    }
    input[strcspn(input, "\r\n")] = '\0';
    separator = strchr(input, '|');
    if (separator == NULL) {
        return 2;
    }
    *separator = '\0';
    initial_value = input;
    replacement_text = separator + 1;
    replacement = strcmp(replacement_text, "NULL") == 0 ? NULL : replacement_text;

    item = cJSON_CreateString(initial_value);
    if (item == NULL) {
        return 3;
    }
    result = cJSON_SetValuestring(item, replacement);
    if (result == NULL) {
        puts("REJECTED");
        cJSON_Delete(item);
        return 0;
    }
    printf("OK:%s\n", result);
    cJSON_Delete(item);
    return 0;
}
