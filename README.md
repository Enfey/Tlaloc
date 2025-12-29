ELF interrogation and manipulation utilities targeting GNU/linux systems. 

1. [LENS](src/lens/) - "Linker-aware ELF navigation system" capable of interrogating ET_DYN, ET_EXEC, and ET_REL objects via memory-mapping object contents and reading them into the corresponding structs provided in [elf.h](https://github.com/torvalds/linux/blob/master/include/uapi/linux/elf.h).
2. TBD
3. TBD
4. TBD

To build this project:
1. cmake -B build -G Ninja
2. ninja -C build

To build a specific executable
1. ninja -C build <execname>

Executables are output to build/bin.