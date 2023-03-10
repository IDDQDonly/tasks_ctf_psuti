#include <stdio.h>
#include <stdlib.h>
#include <string.h>


const char* login()
{

    printf("Enter u login:");
    char *login_name = malloc (sizeof(char)*64);
    login_name = fgets(login_name,64,stdin);
    return login_name;

}

const char* enter_passwd()
{
    printf("Enter u password:");
    char *password = malloc (sizeof(char)*128);
    password = fgets(password,64,stdin);
    return password;
    

}

const char* flag()
{

    unsigned char flag_txt[] = "U2FsdGVkX1/y6Dy0ipW77ctHnLHjIsTJlXoQcQncICdbv6QphpaLD5INorn3Yp0s";
    printf ("%s\n",flag_txt);
    printf("%s\n","use aes128 decoder. key == password");
    printf("%s\n","use the service for example https://crypt-online.ru/crypts/aes/");
    return 0;

}


int check(char* login_name, char* password)
{
    
    int v1 = 0x55 ^ 0x17;
    int v2 = 0x9A - 0x25;
    int v3 = 0x54;
    int v4 = 0xDDC - 0xD88;
    int v5 = 0x99/0x3;
    int v6 = 0xFEDC - 0xFE8A;
    int v7 = 0x22*0x3;
    int v8 = 54*2;
    int v9 = 0x79;
    int len = strlen(login_name);
    int len_p = strlen(password);
    int p1 = 0x61;
    int p2 = 0x52;
    int p3 = 0xABCD - 0xAB8D;
    int p4 = 0xFED - 0xFAA;
    int p5 = 5720 / 55;
    int p6 = 7722 / 99;
    int p7 = (0xAB^0x34)-0x6F;
    int p8 = 0x47+0x29;
    int p9 = (0x1D+0x17)*0x2;
    int p10 = 0x4C*0x2-p9;
    int p11 = 0xFED-0xABC-0x4CF;
    int p12 = (0xAB^0x34)-0x6F + 0x1;
    int p13 = 0xFED-0xABC-0x4CF -0x1;
    int ch = 0;
    int cp =0;
    if ((strcmp(login_name, "\n")!=0) && (len == 10)){ch=ch+1;}
    if (login_name[0] == v1){ch = ch+1;}
    if(login_name[1] == v2){ch = ch+1;}
    if(login_name[2] == v3){ch = ch+1;}
    if(login_name[3] == v4){ch = ch+1;}
    if(login_name[4] == v5){ch = ch+1;}
    if(login_name[5] == v6){ch = ch+1;}
    if(login_name[6] == v7){ch = ch+1;}
    if(login_name[7] == v8){ch = ch+1;}   
    if(login_name[8] == v9){ch = ch+1;}
    if ((strcmp(password, "\n")!=0) && (len_p == 14)){cp = cp+1;}
    if (password[0] == p1){cp = cp+1;}
    if (password[1] == p2){cp = cp+1;}
    if (password[2] == p3){cp = cp+1;}
    if (password[3] == p4){cp = cp+1;}
    if (password[4] == p5){cp = cp+1;}
    if (password[5] == p6){cp = cp+1;}
    if (password[6] == p7){cp = cp+1;}
    if (password[7] == p8){cp = cp+1;}
    if (password[8] == p9){cp = cp+1;}
    if (password[9] == p10){cp = cp+1;}
    if (password[10] == p11){cp = cp+1;}
    if (password[11] == p12){cp = cp+1;}
    if (password[12] == p13){cp = cp+1;}
    if ((ch == 10)&&(cp==14)){
    flag();
    return 0;
    }
    else{
        printf("logo/pass - failed");
    }
}


int main(int argc, char** argv) 
{

printf("hello my friend i'm cat Boris and i'm safe here\n");

    char* cat = R"(
         /  >   フ 
         |  _  _|
        /`ミ _x 彡
       /        |
      /   ヽ　  ﾉ
／￣|    |  |  |
| (￣ヽ__ヽ_)_)
＼二つ)";
    printf("%s\n",cat);
    char login_name[64];
    char password[128];
    strcpy(login_name,login());
    strcpy(password,enter_passwd());
    check(login_name,password);
    
}
