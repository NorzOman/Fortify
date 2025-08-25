package com.facebook.imagepipeline.nativecode;

import com.facebook.soloader.nativeloader.NativeLoader;

/* loaded from: classes.dex */
public class NativeJpegTranscoderSoLoader {
    private static boolean sInitialized;

    public static synchronized void ensure() {
        if (!sInitialized) {
            NativeLoader.loadLibrary("native-imagetranscoder");
            sInitialized = true;
        }
    }
}
