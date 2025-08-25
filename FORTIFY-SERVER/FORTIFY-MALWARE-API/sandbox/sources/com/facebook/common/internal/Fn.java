package com.facebook.common.internal;

import javax.annotation.Nullable;

/* loaded from: classes.dex */
public interface Fn<A, R> {
    @Nullable
    R apply(A a);
}
