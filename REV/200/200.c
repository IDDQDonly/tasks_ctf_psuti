#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>


const char* flag()
{

    unsigned char flag_txt[] = {
  0x46, 0x6c, 0x61, 0x67, 0x7b, 0x43, 0x30, 0x6e, 0x67, 0x72, 0x40, 0x54,
  0x24, 0x5f, 0x55, 0x5f, 0x63, 0x40, 0x6e, 0x5f, 0x46, 0x31, 0x6e, 0x44,
  0x5f, 0x4d, 0x79, 0x5f, 0x43, 0x40, 0x52, 0x44, 0x5f, 0x4e, 0x75, 0x4d,
  0x38, 0x33, 0x52, 0x7d, 0x0a
};

    printf ("%s",flag_txt);
    exit(0);

}

void succeed(char* string) {
    printf("Yes, %s is correct!\n", string);
    flag();

}

void fail(char* string) {
    printf("No, %s is not correct.\n", string);
    exit(1);
}


int getRandomDigit() {
    return rand() % 10;
}

void generateCardNumber(char cardNumber[], int size) {
    for (int i = 0; i < size; i++) {
        cardNumber[i] = '0' + getRandomDigit();
    }
    cardNumber[size] = '\0';
}

int main(int argc, char** argv) {

    srand(time(NULL));
    const int size = 16;
    char card1[size + 1];

    generateCardNumber(card1, size);

    if (argc != 2) {
        printf("Need exactly one argument.\n");
        return -1;
    }
    int correct = (strcmp(card1, argv[1]) == 0);

    if (correct) {
        succeed(argv[1]);
    } else {
        fail(argv[1]);
    }
}

