package com.facebook.react.common;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: JavascriptException.kt */
@Metadata(d1 = {"\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0007\b\u0017\u0018\u00002\u00060\u0001j\u0002`\u0002B\u000f\u0012\u0006\u0010\u0003\u001a\u00020\u0004¢\u0006\u0004\b\u0005\u0010\u0006R\u001c\u0010\u0007\u001a\u0004\u0018\u00010\u0004X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\b\u0010\t\"\u0004\b\n\u0010\u0006¨\u0006\u000b"}, d2 = {"Lcom/facebook/react/common/JavascriptException;", "Ljava/lang/RuntimeException;", "Lkotlin/RuntimeException;", "jsStackTrace", "", "<init>", "(Ljava/lang/String;)V", "extraDataAsJson", "getExtraDataAsJson", "()Ljava/lang/String;", "setExtraDataAsJson", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public class JavascriptException extends RuntimeException {
    private String extraDataAsJson;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public JavascriptException(String jsStackTrace) {
        super(jsStackTrace);
        Intrinsics.checkNotNullParameter(jsStackTrace, "jsStackTrace");
    }

    public final String getExtraDataAsJson() {
        return this.extraDataAsJson;
    }

    public final void setExtraDataAsJson(String str) {
        this.extraDataAsJson = str;
    }
}
