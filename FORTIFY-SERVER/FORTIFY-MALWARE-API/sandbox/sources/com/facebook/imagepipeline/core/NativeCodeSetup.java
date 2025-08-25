package com.facebook.imagepipeline.core;

/* loaded from: classes.dex */
public class NativeCodeSetup {
    private static boolean sUseNativeCode = true;

    private NativeCodeSetup() {
    }

    public static void setUseNativeCode(boolean z) {
        sUseNativeCode = z;
    }

    public static boolean getUseNativeCode() {
        return sUseNativeCode;
    }
}
