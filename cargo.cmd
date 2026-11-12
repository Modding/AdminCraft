@echo off
rem Builds AdminCraft with the Rust + LLVM-MinGW toolchain kept inside this folder
rem (no system install, no Visual Studio needed). Usage: cargo.cmd build --release
set "RUSTUP_HOME=%~dp0.toolchain\rustup"
set "CARGO_HOME=%~dp0.toolchain\cargo"
set "RUSTUP_TOOLCHAIN=stable-x86_64-pc-windows-gnullvm"
set "LLVM_MINGW=%~dp0.toolchain\llvm-mingw-20261104-ucrt-x86_64\bin"
set "PATH=%~dp0.toolchain\cargo\bin;%LLVM_MINGW%;%PATH%"
"%~dp0.toolchain\cargo\bin\cargo.exe" %*
