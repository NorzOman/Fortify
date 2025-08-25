package com.facebook.react.runtime.internal.bolts;

import kotlin.Metadata;

/* compiled from: TaskCompletionSource.kt */
@Metadata(d1 = {"\u00000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0004\b\u0000\u0018\u0000*\u0004\b\u0000\u0010\u00012\u00020\u0002B\u0007¢\u0006\u0004\b\u0003\u0010\u0004J\u0006\u0010\t\u001a\u00020\nJ\u0015\u0010\u000b\u001a\u00020\n2\b\u0010\f\u001a\u0004\u0018\u00018\u0000¢\u0006\u0002\u0010\rJ\u0016\u0010\u000e\u001a\u00020\n2\u000e\u0010\u000f\u001a\n\u0018\u00010\u0010j\u0004\u0018\u0001`\u0011J\u0006\u0010\u0012\u001a\u00020\u0013J\u0015\u0010\u0014\u001a\u00020\u00132\b\u0010\f\u001a\u0004\u0018\u00018\u0000¢\u0006\u0002\u0010\u0015J\u0016\u0010\u0016\u001a\u00020\u00132\u000e\u0010\u000f\u001a\n\u0018\u00010\u0010j\u0004\u0018\u0001`\u0011R\u0017\u0010\u0005\u001a\b\u0012\u0004\u0012\u00028\u00000\u0006¢\u0006\b\n\u0000\u001a\u0004\b\u0007\u0010\b¨\u0006\u0017"}, d2 = {"Lcom/facebook/react/runtime/internal/bolts/TaskCompletionSource;", "TResult", "", "<init>", "()V", "task", "Lcom/facebook/react/runtime/internal/bolts/Task;", "getTask", "()Lcom/facebook/react/runtime/internal/bolts/Task;", "trySetCancelled", "", "trySetResult", "result", "(Ljava/lang/Object;)Z", "trySetError", "error", "Ljava/lang/Exception;", "Lkotlin/Exception;", "setCancelled", "", "setResult", "(Ljava/lang/Object;)V", "setError", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class TaskCompletionSource<TResult> {
    private final Task<TResult> task = new Task<>();

    public final Task<TResult> getTask() {
        return this.task;
    }

    public final boolean trySetCancelled() {
        return this.task.trySetCancelled();
    }

    public final boolean trySetResult(TResult result) {
        return this.task.trySetResult(result);
    }

    public final boolean trySetError(Exception error) {
        return this.task.trySetError(error);
    }

    public final void setCancelled() {
        if (!trySetCancelled()) {
            throw new IllegalStateException("Cannot cancel a completed task.");
        }
    }

    public final void setResult(TResult result) {
        if (!trySetResult(result)) {
            throw new IllegalStateException("Cannot set the result of a completed task.");
        }
    }

    public final void setError(Exception error) {
        if (!trySetError(error)) {
            throw new IllegalStateException("Cannot set the error on a completed task.");
        }
    }
}
