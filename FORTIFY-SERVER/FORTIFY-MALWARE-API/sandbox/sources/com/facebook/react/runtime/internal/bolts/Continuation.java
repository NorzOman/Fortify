package com.facebook.react.runtime.internal.bolts;

import kotlin.Metadata;

/* compiled from: Continuation.kt */
@Metadata(d1 = {"\u0000\u0018\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\b`\u0018\u0000*\u0004\b\u0000\u0010\u0001*\u0004\b\u0001\u0010\u00022\u00020\u0003J\u001d\u0010\u0004\u001a\u0004\u0018\u00018\u00012\f\u0010\u0005\u001a\b\u0012\u0004\u0012\u00028\u00000\u0006H&¢\u0006\u0002\u0010\u0007ø\u0001\u0000\u0082\u0002\u0006\n\u0004\b!0\u0001¨\u0006\bÀ\u0006\u0001"}, d2 = {"Lcom/facebook/react/runtime/internal/bolts/Continuation;", "TTaskResult", "TContinuationResult", "", "then", "task", "Lcom/facebook/react/runtime/internal/bolts/Task;", "(Lcom/facebook/react/runtime/internal/bolts/Task;)Ljava/lang/Object;", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public interface Continuation<TTaskResult, TContinuationResult> {
    TContinuationResult then(Task<TTaskResult> task) throws Exception;
}
