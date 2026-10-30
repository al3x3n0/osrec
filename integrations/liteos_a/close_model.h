#ifndef OSREC_CLOSE_MODEL_H
#define OSREC_CLOSE_MODEL_H
#include <stdint.h>
#include <stddef.h>
int DisassociateProcessFd(int);
void AssociateSystemFd(int,int);
void FreeProcessFd(int);
int close(int);
int get_errno(void);
int SysClose(int);
#endif
