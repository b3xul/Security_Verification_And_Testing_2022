//gcc -m32 -o memory_read memory_read.c

#include <stdio.h>

int main(void) {
    char buffer[128];

    printf("Insert a string: ");
    fgets(buffer, sizeof(buffer), stdin);
    printf(buffer);

    return 0;
}
