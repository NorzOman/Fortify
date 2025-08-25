package com.facebook.soloader;

/* loaded from: classes.dex */
public interface SoFileLoader {
    void load(String str, int i);

    void loadBytes(String str, ElfByteChannel elfByteChannel, int i);
}
