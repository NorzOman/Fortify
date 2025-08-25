package com.facebook.react.uimanager;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: ReactInvalidPropertyException.kt */
@Metadata(d1 = {"\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0005\u0018\u00002\u00060\u0001j\u0002`\u0002B\u001f\u0012\u0006\u0010\u0003\u001a\u00020\u0004\u0012\u0006\u0010\u0005\u001a\u00020\u0004\u0012\u0006\u0010\u0006\u001a\u00020\u0004¢\u0006\u0004\b\u0007\u0010\b¨\u0006\t"}, d2 = {"Lcom/facebook/react/uimanager/ReactInvalidPropertyException;", "Ljava/lang/RuntimeException;", "Lkotlin/RuntimeException;", "property", "", "value", "expectedValues", "<init>", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class ReactInvalidPropertyException extends RuntimeException {
    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public ReactInvalidPropertyException(String property, String value, String expectedValues) {
        super("Invalid React property `" + property + "` with value `" + value + "`, expected " + expectedValues);
        Intrinsics.checkNotNullParameter(property, "property");
        Intrinsics.checkNotNullParameter(value, "value");
        Intrinsics.checkNotNullParameter(expectedValues, "expectedValues");
    }
}
