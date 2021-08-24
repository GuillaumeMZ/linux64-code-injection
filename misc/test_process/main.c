#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int main(void)
{
    printf("My pid is: %d\n", getpid());
    puts("Try to inject me if you can ! Press a key to terminate me...");
    getchar();
    return 0;
}