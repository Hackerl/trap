#include <trap/trap.h>
#include <cstdio>
#include <cstring>

static int (*origin)(const char *, const char *);

int fake(const char *s1, const char *s2) {
    printf("hooked\n");

    if (origin)
        printf("real result: %d\n", origin(s1, s2));

    return 0;
}

int main() {
    if (trap_hook((void *) strcmp, (void *) fake, (void **) &origin) < 0)
        return -1;

    const char *s1 = "hello";
    const char *s2 = "world";

    printf("%s\n", strcmp(s1, s2) == 0 ? "equal" : "not equal");

    if (trap_unhook((void *) strcmp, (void *) origin) < 0)
        return -1;

    printf("%s\n", strcmp(s1, s2) == 0 ? "equal" : "not equal");

    return 0;
}