

#include <iostream>
#include <fstream>
#include <string>
#include <cstdio>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
using namespace std;

FILE* file;

const char HEADER[] =
"*****************************************************************************\\\n"
"|         Never gonna give you up, never gonna let you down, But....         |\n"
"+****************************************************************************+\n";

const char HEADER1[] =
"-------------------------------------------------------------------------------\\\n"
"            ^_^ OMG *_*    I've been waiting for it's really YOU!!!!           |\n"
"-------------------------------------------------------------------------------\n";



const char HEADER2[] =
"-------------------------------------------------------------------------------\\\n"
"            ^_^ YEAH       IT's YOU!! KEEP YOUR FLAG                           |\n"
"-------------------------------------------------------------------------------\n";

int fq(int bbb, int aaa);
int start();
string m = "";
int fq(string re);
int izm(string g);
int f(string p);
int l, kl, aaa, qwez,bbb,ggg;
string g;

string text =
"Never Gonna Give You Up"
"Were no strangers to love"
"You know the rules and so do I"
"A full commitments what Im thinking of"
"You wouldnt get this from any other guy"
"I just wanna tell you how Im feeling"
"Gotta make you understand"
"Never gonna give you up, never gonna let you down"
"Never gonna run aroundand desert you"
"Never gonna make you cry, never gonna say goodbye"
"Never gonna tell a lieand hurt you"
"Weve known each other for so long"
"Your hearts been aching but youre too shy to say it"
"Inside we both know whats been going on"
"We know the game and were gonna play it"
"And if you ask me how Im feeling"
"Dont tell me youre too blind to see"
"(Ooh give you up)"
"(Ooh give you up)"
"(Ooh)never gonna give, never gonna give(give you up)"
"(Ooh)never gonna give, never gonna give(give you up)"
"Weve known each other for so long"
"Your hearts been aching but youre too shy to say it"
"Inside we both know whats been going on"
"We know the game and were gonna play it"
"I just wanna tell you how Im feeling"
"Gotta make you understand";



int delay_per_char = 60;

void text_animation(const char* txt) {
    while (*txt) {
        putchar(*txt++);
        fflush(NULL);
        Sleep(delay_per_char);
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
                Sleep(delay_per_char * 8);
            }
        }
        putchar('.');
    }
}


int main(int argc, char *argv[])
{
    text_animation(HEADER);
    string d = "";
    string c,g,k;
    int b,j,i;
    int a[32];

    text_animation("To check if you know what is hidden here, check if you know the secret combinations: \n");
    cin >> aaa;
    text_animation(" ~>_____ Second,im check.");
    verify_animation(3);
    cout << "\n";
    if (aaa > 0 and aaa < 10 ) {
        for (i = 0; i < text.length(); i++) {
            b = i % aaa;
            if (b == 0) {
                c = d + text[i];
                for (j = 0; j < c.length(); j++) {
                    b = c[j];
                    k = to_string(b);
                    g = g + k;
                }
            }
        }
    }
    
    else {
        text_animation("----------- I say goodbye, SORRY -------------");
        exit(0);
    }
    izm(g);
    start();
    int kl = (g.length() - m.length()) - 200;
    if (kl == qwez) {
        
        fq(aaa,bbb);

    }
    else text_animation("----------- F*CK I say goodbye, THAT's NOT YOU  -------------");
    return 0;
}

int start()
 {

    text_animation(HEADER1);
    cout << "\n";
    text_animation("----- Im WAIT ------ LAST NUBMER  \n");
    cin >> qwez;
    text_animation(" ~>_____ Second,im check.");
    verify_animation(3);
    cout << "\n";
    return 0;

}

int izm(string g) 
{
    int i = 0, b = 0, a = 0;
    string k = "";
    string p;
    text_animation("----- Im WAIT ------ NEXT NUBMER  \n");
    cin >> bbb;
    text_animation(" ~>_____ Second,im check.");
    verify_animation(3);
    cout << "\n";
    if (bbb >= 0 and bbb <= 3) 
    {
        for (i = 0; i < g.length(); i++) 
        {
            a = g[i] % bbb;
            if (a == 1) {
                b = a - 1;
                k = to_string(b);
                p = p + k;
            }
        }
    }
    else 
    {
        text_animation("----------- I say goodbye, SORRY -------------");
        exit(0);
    }
    f(p);


    return m.length(),bbb;
}

int f(string p) 
{
    string j;
    string k = "";
    string q;
    int w = 0,ggg;
    int b = 0;
    int lkl = 5;
    text_animation("----- Im WAIT ------ NEXT NUBMER \n");
    cin >> ggg;
    text_animation(" ~>_____ Second,im check.");
    verify_animation(3);
    cout << "\n";
    if (lkl == ggg)
    {
        for (int i = 0; i < p.length(); i++) {
            j = p[i] ^ text[i];
            for (w; w < p.length(); w++) {
                b = w % lkl;
                if (b == 0) {
                    k = to_string(b);
                    m = m + k;
                }
            }
        }
    }
    else
    {
        text_animation("----------- I say goodbye, SORRY -------------");
        exit(0);
    }
    return m.length();
}


int fq(int bbb, int aaa)
{
    string ro,po;

    int ddd = bbb * aaa;
    for (int i = 0; i < text.length(); i++) {
        if (i % ddd == 0) {
            ro = ro + text[i];
        }
    }

    for (int j = 0; j < ro.length(); j++) {
        if (ro[j] == ' ')
            ro.erase(j, 1);
    }
    for (int j = 0; j < ro.length(); j++) {
        if (ro[j] == ' ')
            ro.erase(j, 1);
    }
    for (int j = 0; j < ro.length(); j++) {
        if (ro[j] != '(')
            po = po + ro[j];

        else break;
    }
    text_animation(HEADER2);
    cout << "\n" << "Flag{" << po << "}\n";
    return 0;
}

