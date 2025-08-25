package com.facebook.react.devsupport;

import android.os.Build;
import kotlin.Metadata;

/* compiled from: WindowOverlayCompat.kt */
@Metadata(d1 = {"\u0000\u0014\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0010\b\n\u0002\b\u0003\bÀ\u0002\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003R\u000e\u0010\u0004\u001a\u00020\u0005X\u0082T¢\u0006\u0002\n\u0000R\u0016\u0010\u0006\u001a\u00020\u00058\u0006X\u0087\u0004¢\u0006\b\n\u0000\u0012\u0004\b\u0007\u0010\u0003¨\u0006\b"}, d2 = {"Lcom/facebook/react/devsupport/WindowOverlayCompat;", "", "<init>", "()V", "TYPE_APPLICATION_OVERLAY", "", "TYPE_SYSTEM_OVERLAY", "getTYPE_SYSTEM_OVERLAY$annotations", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class WindowOverlayCompat {
    public static final WindowOverlayCompat INSTANCE = new WindowOverlayCompat();
    private static final int TYPE_APPLICATION_OVERLAY = 2038;
    public static final int TYPE_SYSTEM_OVERLAY;

    public static /* synthetic */ void getTYPE_SYSTEM_OVERLAY$annotations() {
    }

    private WindowOverlayCompat() {
    }

    static {
        TYPE_SYSTEM_OVERLAY = Build.VERSION.SDK_INT < 26 ? 2006 : TYPE_APPLICATION_OVERLAY;
    }
}
