#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


int a[45] = {119, 95, 82, 80, 16, 92, 1, 89, 62, 68, 44, 74, 13, 71, 41, 21, 119, 107, 2, 14, 98, 2, 1, 103, 125, 68, 124, 119, 42, 69, 37, 46, 64, 13, 88, 7, 67, 30, 57, 76, 67, 7, 68, 60, 16};
int b[45] = {49, 51, 51, 55, 107, 108, 111, 106, 97, 115, 100, 122, 120, 99, 105, 91, 51, 52, 53, 102, 48, 49, 50, 56, 53, 49, 50, 51, 120, 118, 97, 113, 119, 101, 105, 117, 116, 103, 102, 104, 112, 113, 119, 114, 109};


const char HEADER[] = 
"*****************************************************************************\\\n"
"|        beep beep beep bop bop beep bop let me think.... pupupu.....        |\n"
"+****************************************************************************+\n";


double delay_per_char = 1;

void text_animation(const char* txt) {
    while (*txt) {
        putchar(*txt++);
        fflush(NULL);
        sleep(delay_per_char);
    }
}

void verify_animation(unsigned n_cycles) {
    const char states[] = { '/', '-', '\\', '|' };
    for (unsigned i = 0; i < n_cycles; i++) {
        for (int j = 0; j < 3; j++) {
            for (int s = 0; s < sizeof(states); s++) {
                putchar(states[s]);
                putchar('\b');
                fflush(NULL);
                sleep(delay_per_char * 5);
            }
        }
        putchar('.');
    }
}

void jk()
{
int src = 1;
int dst;
char* asd = "a^b";
asm ("mov %1, %0\n\t" // a^b
    "add $1, %0"
    : "=r" (dst)
    : "r" (src));

printf("%d\n", dst);
}
int secret_code(){
    printf("%s","I will give you a secret code, don't forget it\n");
    text_animation(HEADER);
    text_animation(" ~>_____ Second,im check.\n");
    text_animation(" ~>_____ 2 Second,im check.\n");
    text_animation("no password wrong let's do it again\n");
    return 0;
}


int main(int argc, char** argv)
{
    printf("%s","You password or secret_code:");
    char *password = malloc (sizeof(char)*128);
    password = fgets(password,128,stdin);
    secret_code();

}

