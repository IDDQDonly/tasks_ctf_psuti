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

const char* flag(char* login_name,char* password)
{
    printf("%s\n","Flag{");
    printf(login_name);
    printf("_");
    printf(password);
    printf("_W17Hou7_$0uRc3_C0D3}\n");
}


int check(char* login_name, char* password)
{
    if (login_name == "W0R7hy_") 
    {
        if (password ==  "_G37$_Fl@G_@1WayS_") {

            return 0;
        }

    }
    else{
        flag(login_name,password);
    }
}

int main(int argc, char** argv)
{

    char login_name[64];
    char password[128];

    printf("it's veryhard program, but u can...\n");
    strcpy(login_name,login());
    strcpy(password,enter_passwd());
    check(login_name,password);

}