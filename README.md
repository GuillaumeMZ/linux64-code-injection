# Shared library injector for Linux AMD64

Inject shared libraries inside running processes on AMD64 Linux.

## How it works

- The injector uses [ptrace](https://man7.org/linux/man-pages/man2/ptrace.2.html) to get control over the program to inject.
- It pauses its execution, injects a shellcode (a sequence of opcodes) into an executable memory zone of the target then modifies the target's instruction pointer to point to the beginning of the shellcode.
- The injector orders the target to resume its execution. The target executes the shellcode, which contains a call to `dlopen` (injection) / `dlclose` (ejection) to load/unload the desired shared library.
- The dynamic loader loads/unloads the shared library and looks for a constructor (injection) / destructor (ejection). If it is present, it executes it.
- The injector detects when the shellcode's execution is finished and restores the target's initial state so that its execution can continue normally.

## How to build

- Download and install [rustup](https://rustup.rs/):
  
    ```sh
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    ```

- Clone this repository:

    ```sh
    git clone https://github.com/GuillaumeMZ/linux-x64-code-injection.git
    ```

- Navigate inside the cloned folder

    ```sh
    cd linux-x64-code-injection
    ```

- Build the project:

    ```sh
    cargo build --release
    ```

    The generated executable (`injector`) is located in the `target/release` folder.

## How to run

Run:

```sh
./injector --help
```

to see the help.

### Injecting a shared library

Run **as admin** the following command:

```sh
sudo ./injector cli --action inject --pid pid --dl dl_path
```

where:

- `pid` is the PID of the process to inject
- `dl_path` is the **absolute** path of the shared library to inject

You can also customize more advanced options:

- `--libdl <dl_name>` where `dl_name` is the name of the library providing the `dlopen` function that will be used by the injector.
- `--dlopen-name <dlopen_name>` where `dlopen_name` is the name of the dlopen-like function that will be used by the injector to open the desired shared library.

### Ejecting a shared library

Run **as admin** the following command:

```sh
sudo ./injector cli --action eject --pid pid --dl dl_path
```

where:

- `pid` is the PID of the process to inject
- `dl_path` is the **absolute** path of the shared library to eject

You can also customize more advanced options:

- `--libdl <dl_name>` where `dl_name` is the name of the library providing the `dlclose` function that will be used by the ejector.
- `--dlclose-name <dlclose_name>` where `dlclose_name` is the name of the dlclose-like function that will be used by the ejector to close the desired shared library.

## How to write and compile an injectable library

### In C

Create one function that will be called on injection (optional) and another one that will be called on ejection (optional). Each function's prototype must be `void(void)`. Annotate the injection function with GCC's `__attribute__((constructor))` construct, and the ejection function with `__attribute__((destructor))`.

main.c:

```c
#include <stdio.h>

__attribute__((constructor))
void on_inject(void) {
    printf("Hello from injected code !\n");
}

__attribute__((destructor))
void on_eject(void) {
    printf("Goodbye from injected code !\n");
}
```

Compile with:

```sh
gcc main.c -shared -fPIC -o libname.so
```

### In Rust

There is a crate named [ctor](https://crates.io/crates/ctor) that provides an equivalent to GCC's `__attribute__((constructor))` and `__attribute__((destructor))`

Cargo.toml:

```toml
[package]
name = "name"
version = "0.1.0"
edition = "2024"

[lib]
crate-type = ["cdylib"]

[dependencies]
ctor = "0.4.2"
```

src/lib.rs:

```rs
use ctor::{ctor, dtor};

#[ctor]
pub fn on_inject() {
    println!("Hello from injected code !")
}

#[dtor]
pub fn on_eject() {
    println!("Goodbye from injected code !")
}
```

Build with:

```sh
cargo build --release
```

The result (`libname.so`) is located in the `target/release` folder.

## Issues

- Library ejection is not implemented yet.
- The TUI (terminal user interface) is not implemented yet.
