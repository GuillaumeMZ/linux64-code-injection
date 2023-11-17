target("shellcode")
    add_files("src/*.asm")
    set_kind("object")
    set_toolchains("nasm")

target("injector")
    add_deps("shellcode")
    add_files("src/*.c")
    set_languages("c11")