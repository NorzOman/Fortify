package com.facebook.soloader;

/* loaded from: classes.dex */
final class Elf64 {

    static class Dyn {
        public static final int D_TAG = 0;
        public static final int D_UN = 8;

        Dyn() {
        }
    }

    Elf64() {
    }

    static class Ehdr {
        public static final int E_EHSIZE = 52;
        public static final int E_ENTRY = 24;
        public static final int E_FLAGS = 48;
        public static final int E_IDENT = 0;
        public static final int E_MACHINE = 18;
        public static final int E_PHENTSIZE = 54;
        public static final int E_PHNUM = 56;
        public static final int E_PHOFF = 32;
        public static final int E_SHENTSIZE = 58;
        public static final int E_SHNUM = 60;
        public static final int E_SHOFF = 40;
        public static final int E_SHSTRNDX = 62;
        public static final int E_TYPE = 16;
        public static final int E_VERSION = 20;

        Ehdr() {
        }
    }

    static class Phdr {
        public static final int P_ALIGN = 48;
        public static final int P_FILESZ = 32;
        public static final int P_FLAGS = 4;
        public static final int P_MEMSZ = 40;
        public static final int P_OFFSET = 8;
        public static final int P_PADDR = 24;
        public static final int P_TYPE = 0;
        public static final int P_VADDR = 16;

        Phdr() {
        }
    }

    static class Shdr {
        public static final int SH_ADDR = 16;
        public static final int SH_ADDRALIGN = 48;
        public static final int SH_ENTSIZE = 56;
        public static final int SH_FLAGS = 8;
        public static final int SH_INFO = 44;
        public static final int SH_LINK = 40;
        public static final int SH_NAME = 0;
        public static final int SH_OFFSET = 24;
        public static final int SH_SIZE = 32;
        public static final int SH_TYPE = 4;

        Shdr() {
        }
    }
}
