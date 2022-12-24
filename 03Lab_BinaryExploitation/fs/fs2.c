//gcc -m32 -fno-stack-protector -z execstack -g -o fs2 fs2.c

#include <stdio.h>

const char password[] = "This1sm1Str0ngPassw0rd";

int main(int argc, char *argv[]) {
    char buffer[128];

    printf("Insert a string: ");
    fgets(buffer, sizeof(buffer), stdin);
    //printf("%p \n",password);
    printf(buffer);

    return 0;
}
