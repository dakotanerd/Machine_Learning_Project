/* complex_buffer.c
 * intentionally vulnerable C program with several risky APIs and complex flow
 *
 * vulnerabilities: strcpy/strcat overflow, format string, unbounded reads
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void read_username(char *buf, size_t size) {
    // naive read from stdin: allows overflow if input too long
    fgets(buf, size + 100, stdin);  // intentionally wrong: can overflow
    // trim newline
    char *p = strchr(buf, '\n');
    if (p) *p = '\0';
}

void vulnerable_concat(const char *a, const char *b) {
    char buffer[64];
    strcpy(buffer, a);   // unsafe if a is longer than 63
    strcat(buffer, b);   // unsafe concatenation
    printf("Combined: %s\n", buffer);
}

void format_vuln(char *fmt) {
    // format string vulnerability if fmt contains %x/%n etc.
    printf(fmt); // insecure
    printf("\n");
}

int main(int argc, char **argv) {
    char name[32];
    char tmp[128];
    printf("Enter your name: ");
    fflush(stdout);
    // intentionally pass wrong buffer size
    read_username(name, sizeof(name)); // can overflow due to read_username bug

    printf("Hello, ");
    vulnerable_concat("User: ", name);

    printf("Provide format: ");
    fflush(stdout);
    fgets(tmp, sizeof(tmp), stdin);
    // intentionally pass user-controlled string to printf
    format_vuln(tmp);

    // simulate reading untrusted data from env
    char *envp = getenv("CONFIG");
    if (envp) {
        char configbuf[50];
        // possible overflow
        strncpy(configbuf, envp, sizeof(configbuf) - 1);
        configbuf[sizeof(configbuf) - 1] = '\0';
        printf("Loaded config: %s\n", configbuf);
    }
    return 0;
}
