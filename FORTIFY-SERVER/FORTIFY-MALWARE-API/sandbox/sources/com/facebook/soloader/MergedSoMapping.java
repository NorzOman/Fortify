package com.facebook.soloader;

import javax.annotation.Nullable;

/* loaded from: classes.dex */
class MergedSoMapping {
    @Nullable
    static String mapLibName(String str) {
        return null;
    }

    MergedSoMapping() {
    }

    static void invokeJniOnload(String str) {
        throw new IllegalArgumentException("Unknown library: " + str);
    }
}
