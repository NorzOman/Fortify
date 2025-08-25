package com.facebook.react.devsupport;

import kotlin.Metadata;
import kotlin.jvm.JvmStatic;

/* compiled from: InspectorFlags.kt */
@Metadata(d1 = {"\u0000\u0014\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0002\b\u0002\bÇ\u0002\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003J\t\u0010\u0004\u001a\u00020\u0005H\u0087 J\t\u0010\u0006\u001a\u00020\u0005H\u0087 ¨\u0006\u0007"}, d2 = {"Lcom/facebook/react/devsupport/InspectorFlags;", "", "<init>", "()V", "getFuseboxEnabled", "", "getIsProfilingBuild", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class InspectorFlags {
    public static final InspectorFlags INSTANCE = new InspectorFlags();

    @JvmStatic
    public static final native boolean getFuseboxEnabled();

    @JvmStatic
    public static final native boolean getIsProfilingBuild();

    private InspectorFlags() {
    }

    static {
        DevSupportSoLoader.staticInit();
    }
}
