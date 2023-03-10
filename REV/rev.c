#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <cpuid.h>


void succeed(char* string) {
    printf("Yes, %s is correct!\n", string);
    exit(0);
}

void fail(char* string) {
    printf("No, %s is not correct.\n", string);
    exit(1);
}

void shift_int_to_char(int i, char* buff) {
    buff[0] = (i) & 0xFF;
    buff[1] = (i >> 8) & 0xFF;
    buff[2] = (i >> 16) & 0xFF;
    buff[3] = (i >> 24) & 0xFF;
}

int main(int argc, char** argv) {
    if (argc != 2) {
        printf("Need exactly one argument.\n");
        return -1;
    }

    unsigned int eax, ebx, ecx, edx;
    char* buff = malloc(sizeof(char) * 15);
    __get_cpuid(0, &eax, &ebx, &ecx, &edx);
    buff[0] = 'N';
    shift_int_to_char(ebx, buff + 1);
    shift_int_to_char(edx, buff + 5);
    shift_int_to_char(ecx, buff + 9);
    buff[13] = 'Q';
    buff[14] = '\0';

    int correct1 = (strcmp(buff, argv[1]) == 0);
    free(buff);

    if (correct1) {
        succeed(argv[1]);
    } else {
        fail(argv[1]);
    }
}