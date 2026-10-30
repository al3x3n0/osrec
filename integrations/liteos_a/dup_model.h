#ifndef OSREC_DUP_MODEL_H
#define OSREC_DUP_MODEL_H
#include <stdint.h>
#include <stddef.h>
#include "dup_checkpoint.h"
#define CONFIG_NFILE_DESCRIPTORS DUP_SYSTEM_LIMIT
#define EBADF 9
#define EMFILE 24
int GetAssociatedSystemFd(int);
int AllocProcessFd(void);
void files_refer(int);
void AssociateSystemFd(int,int);
int SysDup(int);
#endif
