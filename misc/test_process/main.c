#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int main(void)
{
    printf("pid: %d\n", getpid());
    puts("injectez moi !");
    getchar();
    return 0;
}