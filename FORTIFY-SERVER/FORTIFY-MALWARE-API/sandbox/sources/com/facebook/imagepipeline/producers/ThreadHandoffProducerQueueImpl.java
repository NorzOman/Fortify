package com.facebook.imagepipeline.producers;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.Executor;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: ThreadHandoffProducerQueueImpl.kt */
@Metadata(d1 = {"\u0000*\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0007\u0018\u00002\u00020\u0001B\u000f\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0004\b\u0004\u0010\u0005J\u0010\u0010\u000b\u001a\u00020\f2\u0006\u0010\r\u001a\u00020\nH\u0016J\b\u0010\u000e\u001a\u00020\fH\u0016J\b\u0010\u000f\u001a\u00020\fH\u0016J\b\u0010\u0010\u001a\u00020\fH\u0002J\u0010\u0010\u0011\u001a\u00020\f2\u0006\u0010\r\u001a\u00020\nH\u0016J\b\u0010\u0012\u001a\u00020\u0007H\u0016R\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\u0006\u001a\u00020\u0007X\u0082\u000e¢\u0006\u0002\n\u0000R\u0014\u0010\b\u001a\b\u0012\u0004\u0012\u00020\n0\tX\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\u0013"}, d2 = {"Lcom/facebook/imagepipeline/producers/ThreadHandoffProducerQueueImpl;", "Lcom/facebook/imagepipeline/producers/ThreadHandoffProducerQueue;", "executor", "Ljava/util/concurrent/Executor;", "<init>", "(Ljava/util/concurrent/Executor;)V", "queueing", "", "runnableList", "Ljava/util/Deque;", "Ljava/lang/Runnable;", "addToQueueOrExecute", "", "runnable", "startQueueing", "stopQueuing", "execInQueue", "remove", "isQueueing", "imagepipeline_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class ThreadHandoffProducerQueueImpl implements ThreadHandoffProducerQueue {
    private final Executor executor;
    private boolean queueing;
    private final Deque<Runnable> runnableList;

    public ThreadHandoffProducerQueueImpl(Executor executor) {
        Intrinsics.checkNotNullParameter(executor, "executor");
        this.executor = executor;
        this.runnableList = new ArrayDeque();
    }

    @Override // com.facebook.imagepipeline.producers.ThreadHandoffProducerQueue
    public synchronized void addToQueueOrExecute(Runnable runnable) {
        Intrinsics.checkNotNullParameter(runnable, "runnable");
        if (this.queueing) {
            this.runnableList.add(runnable);
        } else {
            this.executor.execute(runnable);
        }
    }

    @Override // com.facebook.imagepipeline.producers.ThreadHandoffProducerQueue
    public synchronized void startQueueing() {
        this.queueing = true;
    }

    @Override // com.facebook.imagepipeline.producers.ThreadHandoffProducerQueue
    public synchronized void stopQueuing() {
        this.queueing = false;
        execInQueue();
    }

    private final void execInQueue() {
        while (!this.runnableList.isEmpty()) {
            this.executor.execute(this.runnableList.pop());
        }
        this.runnableList.clear();
    }

    @Override // com.facebook.imagepipeline.producers.ThreadHandoffProducerQueue
    public synchronized void remove(Runnable runnable) {
        Intrinsics.checkNotNullParameter(runnable, "runnable");
        this.runnableList.remove(runnable);
    }

    @Override // com.facebook.imagepipeline.producers.ThreadHandoffProducerQueue
    public synchronized boolean isQueueing() {
        return this.queueing;
    }
}
