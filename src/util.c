#include "include/util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

void print_banner(void) {
    printf("\033[34m");
    printf("██╗      ██████╗  ██████╗██╗  ██╗██████╗ \n");
    printf("██║     ██╔═══██╗██╔════╝██║ ██╔╝██╔══██╗\n");
    printf("██║     ██║   ██║██║     █████╔╝ ██████╔╝\n");
    printf("██║     ██║   ██║██║     ██╔═██╗ ██╔══██╗\n");
    printf("███████╗╚██████╔╝╚██████╗██║  ██╗██║  ██║\n");
    printf("╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝\n");
    printf("                                          \n");
    printf("Lockr - Encrypted File Locker\n | v0.0.1");
    printf("\033[0m\n");
}

void print_help(const char *progname) {
    printf("\033[33mUsage:\033[0m\n");
    printf("  %s <lock|unlock> <file> [options]\n\n", progname);
    printf("\033[33mOptions:\033[0m\n");
    printf("  --rm                         Remove input file after locking\n");
    printf("  --encrypt-key=<key>          Use custom encryption key for locking (prompts if no key given)\n");
    printf("  --password <pass>            Provide password inline to unlock\n");
    printf("  --password=<pass>            Same as above\n");
    printf("  -h, --help                  Show this help message\n\n");
}

void print_error(const char *msg) {
    fprintf(stderr, "\033[31mError:\033[0m %s\n", msg);
}

void print_info(const char *msg) {
    fprintf(stdout, "\033[32m%s\033[0m\n", msg);
}

char *prompt_password(const char *prompt) {
    struct termios oldt, newt;
    char *buffer = malloc(256);
    if (!buffer) return NULL;

    printf("%s", prompt);
    fflush(stdout);

    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    fgets(buffer, 256, stdin);
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    printf("\n");

    buffer[strcspn(buffer, "\n")] = 0;
    return buffer;
}
