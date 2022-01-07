#ifndef TRAP_TRAP_H
#define TRAP_TRAP_H

#ifdef __cplusplus
extern "C" {
#endif

int hook(void *address, void *replace, void **backup);
int unhook(void *address, void *backup);

#ifdef __cplusplus
}
#endif

#endif //TRAP_TRAP_H
