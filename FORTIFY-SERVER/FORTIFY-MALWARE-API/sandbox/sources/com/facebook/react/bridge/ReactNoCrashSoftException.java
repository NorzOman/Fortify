package com.facebook.react.bridge;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: ReactNoCrashSoftException.kt */
@Metadata(d1 = {"\u0000\u001e\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0003\n\u0002\u0010\u0003\n\u0002\b\u0003\b\u0016\u0018\u00002\u00060\u0001j\u0002`\u0002B\u0011\b\u0016\u0012\u0006\u0010\u0003\u001a\u00020\u0004¢\u0006\u0004\b\u0005\u0010\u0006B\u0011\b\u0016\u0012\u0006\u0010\u0007\u001a\u00020\b¢\u0006\u0004\b\u0005\u0010\tB\u001b\b\u0016\u0012\u0006\u0010\u0003\u001a\u00020\u0004\u0012\b\u0010\u0007\u001a\u0004\u0018\u00010\b¢\u0006\u0004\b\u0005\u0010\n¨\u0006\u000b"}, d2 = {"Lcom/facebook/react/bridge/ReactNoCrashSoftException;", "Ljava/lang/RuntimeException;", "Lkotlin/RuntimeException;", "m", "", "<init>", "(Ljava/lang/String;)V", "e", "", "(Ljava/lang/Throwable;)V", "(Ljava/lang/String;Ljava/lang/Throwable;)V", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public class ReactNoCrashSoftException extends RuntimeException {
    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public ReactNoCrashSoftException(String m) {
        super(m);
        Intrinsics.checkNotNullParameter(m, "m");
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public ReactNoCrashSoftException(Throwable e) {
        super(e);
        Intrinsics.checkNotNullParameter(e, "e");
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public ReactNoCrashSoftException(String m, Throwable th) {
        super(m, th);
        Intrinsics.checkNotNullParameter(m, "m");
    }
}
