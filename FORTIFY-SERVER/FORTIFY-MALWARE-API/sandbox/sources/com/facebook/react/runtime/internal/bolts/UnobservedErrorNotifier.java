package com.facebook.react.runtime.internal.bolts;

import com.facebook.react.runtime.internal.bolts.Task;
import kotlin.Metadata;

/* compiled from: UnobservedErrorNotifier.kt */
@Metadata(d1 = {"\u0000\u001a\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0002\b\u0002\b\u0000\u0018\u00002\u00020\u0001B\u0015\u0012\f\u0010\u0002\u001a\b\u0012\u0002\b\u0003\u0018\u00010\u0003¢\u0006\u0004\b\u0004\u0010\u0005J\b\u0010\u0006\u001a\u00020\u0007H\u0004J\u0006\u0010\b\u001a\u00020\u0007R\u0014\u0010\u0002\u001a\b\u0012\u0002\b\u0003\u0018\u00010\u0003X\u0082\u000e¢\u0006\u0002\n\u0000¨\u0006\t"}, d2 = {"Lcom/facebook/react/runtime/internal/bolts/UnobservedErrorNotifier;", "", "task", "Lcom/facebook/react/runtime/internal/bolts/Task;", "<init>", "(Lcom/facebook/react/runtime/internal/bolts/Task;)V", "finalize", "", "setObserved", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class UnobservedErrorNotifier {
    private Task<?> task;

    public UnobservedErrorNotifier(Task<?> task) {
        this.task = task;
    }

    protected final void finalize() {
        Task.UnobservedExceptionHandler unobservedExceptionHandler;
        Task<?> task = this.task;
        if (task == null || (unobservedExceptionHandler = Task.getUnobservedExceptionHandler()) == null) {
            return;
        }
        unobservedExceptionHandler.unobservedException(task, new UnobservedTaskException(task.getError()));
    }

    public final void setObserved() {
        this.task = null;
    }
}
