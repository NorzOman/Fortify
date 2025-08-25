package com.facebook.react.bridge;

import androidx.core.app.NotificationCompat;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: RetryableMountingLayerException.kt */
@Metadata(d1 = {"\u0000\u001e\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0003\n\u0002\u0010\u0003\n\u0002\b\u0003\u0018\u00002\u00060\u0001j\u0002`\u0002B\u0011\b\u0016\u0012\u0006\u0010\u0003\u001a\u00020\u0004¢\u0006\u0004\b\u0005\u0010\u0006B\u0011\b\u0016\u0012\u0006\u0010\u0007\u001a\u00020\b¢\u0006\u0004\b\u0005\u0010\tB\u001b\b\u0016\u0012\u0006\u0010\u0003\u001a\u00020\u0004\u0012\b\u0010\u0007\u001a\u0004\u0018\u00010\b¢\u0006\u0004\b\u0005\u0010\n¨\u0006\u000b"}, d2 = {"Lcom/facebook/react/bridge/RetryableMountingLayerException;", "Ljava/lang/RuntimeException;", "Lkotlin/RuntimeException;", NotificationCompat.CATEGORY_MESSAGE, "", "<init>", "(Ljava/lang/String;)V", "e", "", "(Ljava/lang/Throwable;)V", "(Ljava/lang/String;Ljava/lang/Throwable;)V", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class RetryableMountingLayerException extends RuntimeException {
    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public RetryableMountingLayerException(String msg) {
        super(msg);
        Intrinsics.checkNotNullParameter(msg, "msg");
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public RetryableMountingLayerException(Throwable e) {
        super(e);
        Intrinsics.checkNotNullParameter(e, "e");
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public RetryableMountingLayerException(String msg, Throwable th) {
        super(msg, th);
        Intrinsics.checkNotNullParameter(msg, "msg");
    }
}
