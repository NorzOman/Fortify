package com.facebook.react.views.text.internal.span;

import kotlin.Metadata;

/* compiled from: ReactTagSpan.kt */
@Metadata(d1 = {"\u0000\u0012\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0002\b\u0005\u0018\u00002\u00020\u0001B\u000f\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0004\b\u0004\u0010\u0005R\u0011\u0010\u0002\u001a\u00020\u0003¢\u0006\b\n\u0000\u001a\u0004\b\u0006\u0010\u0007¨\u0006\b"}, d2 = {"Lcom/facebook/react/views/text/internal/span/ReactTagSpan;", "Lcom/facebook/react/views/text/internal/span/ReactSpan;", "reactTag", "", "<init>", "(I)V", "getReactTag", "()I", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class ReactTagSpan implements ReactSpan {
    private final int reactTag;

    public ReactTagSpan(int i) {
        this.reactTag = i;
    }

    public final int getReactTag() {
        return this.reactTag;
    }
}
