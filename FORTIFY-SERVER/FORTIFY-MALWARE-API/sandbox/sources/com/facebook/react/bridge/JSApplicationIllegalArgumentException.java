package com.facebook.react.bridge;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: JSApplicationIllegalArgumentException.kt */
@Metadata(d1 = {"\u0000\u001a\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0003\n\u0002\u0010\u0003\n\u0002\b\u0002\u0018\u00002\u00020\u0001B\u0011\b\u0016\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0004\b\u0004\u0010\u0005B\u0019\b\u0016\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0006\u001a\u00020\u0007¢\u0006\u0004\b\u0004\u0010\b¨\u0006\t"}, d2 = {"Lcom/facebook/react/bridge/JSApplicationIllegalArgumentException;", "Lcom/facebook/react/bridge/JSApplicationCausedNativeException;", "detailMessage", "", "<init>", "(Ljava/lang/String;)V", "t", "", "(Ljava/lang/String;Ljava/lang/Throwable;)V", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class JSApplicationIllegalArgumentException extends JSApplicationCausedNativeException {
    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public JSApplicationIllegalArgumentException(String detailMessage) {
        super(detailMessage);
        Intrinsics.checkNotNullParameter(detailMessage, "detailMessage");
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public JSApplicationIllegalArgumentException(String detailMessage, Throwable t) {
        super(detailMessage, t);
        Intrinsics.checkNotNullParameter(detailMessage, "detailMessage");
        Intrinsics.checkNotNullParameter(t, "t");
    }
}
