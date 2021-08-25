#include <stdio.h>
#include <stdlib.h>
#include <pthread.h> //we are using pthread so we must link with libpthread. it's okay if the target process doesn't link against pthread, because the dynamic linker (invoked by dlopen) will load libpthread for us.
//if you want to unload libpthread after the shared object has done its work, you have to manually call dlclose: it also means you have to load pthread manually with dlopen to get its handle.

void* runner(void* data) //data is log_file
{
    FILE* log_file = data;
    fputs("Je suis dans le thread !\n", log_file);
    fclose(log_file);

    pthread_exit(EXIT_SUCCESS); //stops the thread
}

__attribute__((constructor))
void on_load(void)
{
    FILE* log_file = fopen("/home/guillaume/Documents/log.txt", "w");
    if(log_file == NULL)
        //erreur
        return;

    fputs("on_load: le thread est sur le point d'etre cree.\n", log_file);

    pthread_t my_thread;
    if(pthread_create(&my_thread, NULL, runner, log_file) != 0)
    {
        //error
        fclose(log_file);
        return;
    }
        
    //we don't use pthread_join because we want the tracee to get control back as soon as possible
}