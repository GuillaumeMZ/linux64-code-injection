#include <sys/types.h>
#include <sys/user.h>
#include <signal.h> //siginfo_t
#include <stdint.h>

typedef struct user_regs_struct registers_t;

void attach_process(pid_t pid);
void detach_process(pid_t pid);
void resume_process(pid_t pid);
void resume_process_singlestep(pid_t pid); //for debugging the injector

void get_registers(pid_t pid, registers_t* save);
void set_registers(pid_t pid, const registers_t* registers);

uint64_t* read_memory(pid_t pid, void* address, size_t words_to_read); //ajouter size_t* words_read
void write_memory(pid_t pid, void* address, const uint64_t* buffer, size_t words_to_write); //ajouter size_t* words_written


/*
    injection:
        s'attacher au processus //ptrace(PTRACE_ATTACH, pid, NULL, NULL); /proc/sys/kernel/yama/ptrace_scope doit contenir 0 (à faire dans le script)
        sauvegarder les registres ptrace(PTRACE_GETREGS, pid, NULL, sauvegarde); (voir sys/user.h pour le format de sauvegarde)
        trouver l'endroit où injecter le shellcode (une zone mémoire avec des permissions en execution, ptrace peut bypass les permissions en lecture/écriture)
        sauvegarder cette zone mémoire afin de la restaurer ensuite PTRACE_PEEKDATA
        y injecter le shellcode // ptrace(PTRACE_POKEDATA, pid, address, data (64 bits));
        modifier rip pour le placer à l'endroit où se trouve le shellcode //ptrace(PTRACE_SETREGS, pid, NULL, sauvegarde);
        modifier rsp si besoin pour l'aligner rsp = rsp - rsp%16
        reprendre l'execution du processus pour executer le shellcode //ptrace(PTRACE_CONT, pid, NULL, NULL);
        une fois le shellcode terminé, remettre le processus en pause //int 3 dans le shellcode
        sortir le sigtrap
        restaurer les registres //ptrace(PTRACE_SETREGS, pid, NULL, sauvegarde);
        se détacher du process //ptrace(PTRACE_DETACH, pid, NULL, NULL);
        vérifier que la bibliothèque a été injectée (script)
        mettre /proc/sys/kernel/yama/ptrace_scope à 2 (script)

    à implémenter:
        attach_process (OK)
        detach_process (OK)
        resume_process (OK)
        get_registers (OK)
        set_registers (OK)

        fetch_signal ?
        peek_signal ?

        read_memory (OK)
        write_memory (OK)
*/