package com.facebook.soloader;

import javax.annotation.Nullable;

/* loaded from: classes.dex */
public interface ExternalSoMapping {
    void invokeJniOnload(String str);

    @Nullable
    String mapLibName(String str);
}
