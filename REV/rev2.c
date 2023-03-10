#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

const char HEADER[] =
"*****************************************************************************\\\n"
"|                         hello my friend, it's u or not?                    |\n"
"+****************************************************************************+\n";

const char ACCESS_DENIED[] = "oops, denied\n";

const useconds_t delay_per_char = 10000;

void text_animation(const char *txt) {
  while (*txt) {
    putchar(*txt++);
    fflush(NULL);
    usleep(delay_per_char);
  }
}

void verify_animation(unsigned n_cycles) {
  const char states[] = {'/', '-', '\\', '|'};
  for (unsigned i = 0; i < n_cycles; i++) {
    for (int j = 0; j < 3; j++) {
      for (int s = 0; s < sizeof(states); s++) {
        putchar(states[s]);
        putchar('\b');
        fflush(NULL);
        usleep(delay_per_char * 10);
      }
    }
    putchar('.');
  }
}

int main(int argc, char *argv[]) {
  text_animation(HEADER);
  if (argc != 3) {
    printf("[ERROR] Login missing\n");
    printf("Usage: %s <username> <password>\n", argv[0]);
    return 1;
  } else {
    text_animation(" ~>_____ Second,im check.");
    verify_animation(3);
    if (strcmp(argv[1], "0n3_PPASDLLL")) {
      putchar('\n');
      text_animation(ACCESS_DENIED);
      text_animation(" ~>_____ Bad username\n");
      return 1;
    }

    char *buffer = (char *)malloc(strlen(argv[2]) + 1);
    strcpy(buffer, argv[2]);
    for (size_t i = 0; i < strlen(buffer) >> 1; i++) {
      char c = buffer[i];
      buffer[i] = buffer[strlen(buffer) - i - 1];
      buffer[strlen(buffer) - i - 1] = c;
    }

    verify_animation(3);
    if (!strcmp(buffer, "DSAA_GCCC_REEE_QDSSA_p_P")) { 
      text_animation("Correct!\n");
      text_animation("Hello, my friend!\n");
      char local_buf[128];
      snprintf(local_buf, sizeof(local_buf), "FLAG{%s}\n", argv[2]);
      text_animation(local_buf);
    } else {
      text_animation(ACCESS_DENIED);
      text_animation(" ~> Bad password\n");
    }
  }

  return 0;
}
