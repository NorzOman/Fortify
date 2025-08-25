package com.facebook.soloader.nativeloader;

import java.io.IOException;

/* loaded from: classes.dex */
public class NativeLoader {
    private static NativeLoaderDelegate sDelegate;

    private NativeLoader() {
    }

    public static boolean loadLibrary(String str) {
        return loadLibrary(str, 0);
    }

    public static boolean loadLibrary(String str, int i) {
        NativeLoaderDelegate nativeLoaderDelegate;
        synchronized (NativeLoader.class) {
            nativeLoaderDelegate = sDelegate;
            if (nativeLoaderDelegate == null) {
                throw new IllegalStateException("NativeLoader has not been initialized.  To use standard native library loading, call NativeLoader.init(new SystemDelegate()).");
            }
        }
        return nativeLoaderDelegate.loadLibrary(str, i);
    }

    public static String getLibraryPath(String str) throws IOException {
        NativeLoaderDelegate nativeLoaderDelegate;
        synchronized (NativeLoader.class) {
            nativeLoaderDelegate = sDelegate;
            if (nativeLoaderDelegate == null) {
                throw new IllegalStateException("NativeLoader has not been initialized.  To use standard native library loading, call NativeLoader.init(new SystemDelegate()).");
            }
        }
        return nativeLoaderDelegate.getLibraryPath(str);
    }

    public static int getSoSourcesVersion() {
        NativeLoaderDelegate nativeLoaderDelegate;
        synchronized (NativeLoader.class) {
            nativeLoaderDelegate = sDelegate;
            if (nativeLoaderDelegate == null) {
                throw new IllegalStateException("NativeLoader has not been initialized.  To use standard native library loading, call NativeLoader.init(new SystemDelegate()).");
            }
        }
        return nativeLoaderDelegate.getSoSourcesVersion();
    }

    public static void init(NativeLoaderDelegate nativeLoaderDelegate) {
        synchronized (NativeLoader.class) {
            if (sDelegate != null) {
                throw new IllegalStateException("Cannot re-initialize NativeLoader.");
            }
            sDelegate = nativeLoaderDelegate;
        }
    }

    public static boolean isInitialized() {
        boolean z;
        synchronized (NativeLoader.class) {
            z = sDelegate != null;
        }
        return z;
    }

    public static void initIfUninitialized(NativeLoaderDelegate nativeLoaderDelegate) {
        if (isInitialized()) {
            return;
        }
        init(nativeLoaderDelegate);
    }
}
