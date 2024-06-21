#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("Error: this injector only works on x86_64 Linux.");

fn main() {
    println!("Hello, world!");
}
