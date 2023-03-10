#include <stdio.h>
#include <string.h>
#include <stdlib.h>



const char* flag(char* string)
{

    unsigned char flag_txt[] = "U2FsdGVkX19Yz1mZZ3WWv7RNCra1sPZ69OTq/aRSu/Oonh6ggAstZWQxbP0FnOjf3p2EI5/Q0tet85lUjVh4yA==";
    if (string){printf ("%s\n",flag_txt);
    printf("%s\n","use aes128 decoder. key secret word");
    printf("%s\n","use the service for example https://crypt-online.ru/crypts/aes/");}

    return 0;

}

void fail(){
    printf("nope");
    exit(1);
}

void advanced_check(char* string){
    char* v2 = string;
    if ( v2[0] != 0x38){
        fail();
    }
    else{
        if(v2[1] != v2[2]){
            fail();
        }
        else{
            if (v2[0] != v2[3]){
                fail();
            }
            else{
                if (v2[4] != 0x24){
                    fail();
                }
                else{
                    flag(v2);
                }
            }
        }
    }
}


int main(int argc, char** argv){

    if (argc != 2) {
    printf("Need exactly one argument.\n");
    return -1;
    }
    
    int v1 = atoi(argv[1]);
    if (v1%2 != 0){
        fail();
    }
    else{
        if (strlen(argv[1]) <= 4){
            fail();
        }
        else{
            advanced_check(argv[1]);
        }
        }
}
