#include "utils.h"
#include <stdio.h>
#include <stdlib.h>

void fatal_error(const char* name)
{
    perror(name);
    exit(1);
}