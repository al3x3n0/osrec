#ifndef OSREC_LINUX_STDIO_H
#define OSREC_LINUX_STDIO_H
/* Only the output operations used by the standalone replay. */
typedef struct { int fd; } FILE;
extern FILE *stderr;
int fputs(const char *text, FILE *stream);
int puts(const char *text);
#endif
