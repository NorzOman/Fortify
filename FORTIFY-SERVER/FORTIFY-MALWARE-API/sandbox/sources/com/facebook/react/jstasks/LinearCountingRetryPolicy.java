package com.facebook.react.jstasks;

import kotlin.Metadata;

/* compiled from: LinearCountingRetryPolicy.kt */
@Metadata(d1 = {"\u0000\u001a\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0002\b\u0004\n\u0002\u0010\u000b\n\u0002\b\u0006\u0018\u00002\u00020\u0001B\u0017\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0003¢\u0006\u0004\b\u0005\u0010\u0006J\b\u0010\u0007\u001a\u00020\bH\u0016J\b\u0010\f\u001a\u00020\u0001H\u0016J\b\u0010\r\u001a\u00020\u0001H\u0016R\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\u0004\u001a\u00020\u0003X\u0082\u0004¢\u0006\u0002\n\u0000R\u0014\u0010\t\u001a\u00020\u0003X\u0096\u0004¢\u0006\b\n\u0000\u001a\u0004\b\n\u0010\u000b¨\u0006\u000e"}, d2 = {"Lcom/facebook/react/jstasks/LinearCountingRetryPolicy;", "Lcom/facebook/react/jstasks/HeadlessJsTaskRetryPolicy;", "retryAttempts", "", "delayBetweenAttemptsInMs", "<init>", "(II)V", "canRetry", "", "delay", "getDelay", "()I", "update", "copy", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class LinearCountingRetryPolicy implements HeadlessJsTaskRetryPolicy {
    private final int delay;
    private final int delayBetweenAttemptsInMs;
    private final int retryAttempts;

    public LinearCountingRetryPolicy(int i, int i2) {
        this.retryAttempts = i;
        this.delayBetweenAttemptsInMs = i2;
        this.delay = i2;
    }

    @Override // com.facebook.react.jstasks.HeadlessJsTaskRetryPolicy
    public boolean canRetry() {
        return this.retryAttempts > 0;
    }

    @Override // com.facebook.react.jstasks.HeadlessJsTaskRetryPolicy
    public int getDelay() {
        return this.delay;
    }

    @Override // com.facebook.react.jstasks.HeadlessJsTaskRetryPolicy
    public HeadlessJsTaskRetryPolicy update() {
        int i = this.retryAttempts - 1;
        if (i > 0) {
            return new LinearCountingRetryPolicy(i, this.delayBetweenAttemptsInMs);
        }
        return NoRetryPolicy.INSTANCE;
    }

    @Override // com.facebook.react.jstasks.HeadlessJsTaskRetryPolicy
    public HeadlessJsTaskRetryPolicy copy() {
        return new LinearCountingRetryPolicy(this.retryAttempts, this.delayBetweenAttemptsInMs);
    }
}
