#include <stdio.h>

__attribute__((constructor))
void say_hello(void)
{
    printf("Hello, world from injected code !\n");
}