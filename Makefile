injector-release: shellcode
	gcc ./src/main.c ./src/shellcode.c ./src/procutils.c ./src/utils.c ./bin/shellcode.o -o ./bin/injector

injector-debug: shellcode
	gcc ./src/main.c ./src/shellcode.c ./src/procutils.c ./src/utils.c ./bin/shellcode.o -g -o ./bin/injector-debug

shellcode:
	nasm -felf64 ./src/shellcode.asm -o ./bin/shellcode.o

test_so:
	gcc ./src/test_so.c -shared -fPIC -o ./bin/test_so.so

run_test_process: test_process
	./misc/test_process/test_process

test_process:
	gcc ./misc/test_process/main.c -o ./misc/test_process/test_process