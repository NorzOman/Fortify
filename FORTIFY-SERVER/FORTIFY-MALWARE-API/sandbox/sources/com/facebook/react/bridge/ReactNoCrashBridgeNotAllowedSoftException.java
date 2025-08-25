package com.facebook.react.bridge;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: ReactNoCrashBridgeNotAllowedSoftException.kt */
@Metadata(d1 = {"\u0000\u001a\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0003\n\u0002\u0010\u0003\n\u0002\b\u0003\u0018\u00002\u00020\u0001B\u0011\b\u0016\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0004\b\u0004\u0010\u0005B\u0011\b\u0016\u0012\u0006\u0010\u0006\u001a\u00020\u0007¢\u0006\u0004\b\u0004\u0010\bB\u0019\b\u0016\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0006\u001a\u00020\u0007¢\u0006\u0004\b\u0004\u0010\t¨\u0006\n"}, d2 = {"Lcom/facebook/react/bridge/ReactNoCrashBridgeNotAllowedSoftException;", "Lcom/facebook/react/bridge/ReactNoCrashSoftException;", "m", "", "<init>", "(Ljava/lang/String;)V", "e", "", "(Ljava/lang/Throwable;)V", "(Ljava/lang/String;Ljava/lang/Throwable;)V", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class ReactNoCrashBridgeNotAllowedSoftException extends ReactNoCrashSoftException {
    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public ReactNoCrashBridgeNotAllowedSoftException(String m) {
        super(m);
        Intrinsics.checkNotNullParameter(m, "m");
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public ReactNoCrashBridgeNotAllowedSoftException(Throwable e) {
        super(e);
        Intrinsics.checkNotNullParameter(e, "e");
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public ReactNoCrashBridgeNotAllowedSoftException(String m, Throwable e) {
        super(m, e);
        Intrinsics.checkNotNullParameter(m, "m");
        Intrinsics.checkNotNullParameter(e, "e");
    }
}
