build: injection_shellcode ejection_shellcode
	gcc ./src/*.c ./bin/*.o -o ./bin/injector

injection_shellcode:
	nasm -felf64 ./src/injection_shellcode.asm -o ./bin/injection_shellcode.o

ejection_shellcode:
	nasm -felf64 ./src/ejection_shellcode.asm -o ./bin/ejection_shellcode.o