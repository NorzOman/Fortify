package com.facebook.jni;

import com.facebook.soloader.nativeloader.NativeLoader;

/* loaded from: classes.dex */
public class ThreadScopeSupport {
    private static native void runStdFunctionImpl(long j);

    static {
        NativeLoader.loadLibrary("fbjni");
    }

    private static void runStdFunction(long j) {
        runStdFunctionImpl(j);
    }
}
