package com.facebook.common.memory;

import javax.annotation.Nullable;

/* loaded from: classes.dex */
public class NoOpMemoryTrimmableRegistry implements MemoryTrimmableRegistry {

    @Nullable
    private static NoOpMemoryTrimmableRegistry sInstance;

    @Override // com.facebook.common.memory.MemoryTrimmableRegistry
    public void registerMemoryTrimmable(MemoryTrimmable memoryTrimmable) {
    }

    @Override // com.facebook.common.memory.MemoryTrimmableRegistry
    public void unregisterMemoryTrimmable(MemoryTrimmable memoryTrimmable) {
    }

    public static synchronized NoOpMemoryTrimmableRegistry getInstance() {
        if (sInstance == null) {
            sInstance = new NoOpMemoryTrimmableRegistry();
        }
        return sInstance;
    }
}
