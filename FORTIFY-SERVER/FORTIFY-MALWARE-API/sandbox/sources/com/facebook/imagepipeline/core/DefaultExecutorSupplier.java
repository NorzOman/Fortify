package com.facebook.imagepipeline.core;

import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: DefaultExecutorSupplier.kt */
@Metadata(d1 = {"\u0000\"\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\t\u0018\u0000 \u00142\u00020\u0001:\u0001\u0014B\u000f\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0004\b\u0004\u0010\u0005J\b\u0010\r\u001a\u00020\u0007H\u0016J\b\u0010\u000e\u001a\u00020\u0007H\u0016J\b\u0010\u000f\u001a\u00020\u0007H\u0016J\b\u0010\u0010\u001a\u00020\u0007H\u0016J\n\u0010\u0011\u001a\u0004\u0018\u00010\fH\u0016J\b\u0010\u0012\u001a\u00020\u0007H\u0016J\b\u0010\u0013\u001a\u00020\u0007H\u0016R\u000e\u0010\u0006\u001a\u00020\u0007X\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\b\u001a\u00020\u0007X\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\t\u001a\u00020\u0007X\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\n\u001a\u00020\u0007X\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\u000b\u001a\u00020\fX\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\u0015"}, d2 = {"Lcom/facebook/imagepipeline/core/DefaultExecutorSupplier;", "Lcom/facebook/imagepipeline/core/ExecutorSupplier;", "numCpuBoundThreads", "", "<init>", "(I)V", "ioBoundExecutor", "Ljava/util/concurrent/Executor;", "decodeExecutor", "backgroundExecutor", "lightWeightBackgroundExecutor", "backgroundScheduledExecutorService", "Ljava/util/concurrent/ScheduledExecutorService;", "forLocalStorageRead", "forLocalStorageWrite", "forDecode", "forBackgroundTasks", "scheduledExecutorServiceForBackgroundTasks", "forLightweightBackgroundTasks", "forThumbnailProducer", "Companion", "imagepipeline-base_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class DefaultExecutorSupplier implements ExecutorSupplier {
    private static final int NUM_IO_BOUND_THREADS = 2;
    private static final int NUM_LIGHTWEIGHT_BACKGROUND_THREADS = 1;
    private final Executor backgroundExecutor;
    private final ScheduledExecutorService backgroundScheduledExecutorService;
    private final Executor decodeExecutor;
    private final Executor ioBoundExecutor;
    private final Executor lightWeightBackgroundExecutor;

    public DefaultExecutorSupplier(int i) {
        ExecutorService executorServiceNewFixedThreadPool = Executors.newFixedThreadPool(2, new PriorityThreadFactory(10, "FrescoIoBoundExecutor", true));
        Intrinsics.checkNotNullExpressionValue(executorServiceNewFixedThreadPool, "newFixedThreadPool(...)");
        this.ioBoundExecutor = executorServiceNewFixedThreadPool;
        ExecutorService executorServiceNewFixedThreadPool2 = Executors.newFixedThreadPool(i, new PriorityThreadFactory(10, "FrescoDecodeExecutor", true));
        Intrinsics.checkNotNullExpressionValue(executorServiceNewFixedThreadPool2, "newFixedThreadPool(...)");
        this.decodeExecutor = executorServiceNewFixedThreadPool2;
        ExecutorService executorServiceNewFixedThreadPool3 = Executors.newFixedThreadPool(i, new PriorityThreadFactory(10, "FrescoBackgroundExecutor", true));
        Intrinsics.checkNotNullExpressionValue(executorServiceNewFixedThreadPool3, "newFixedThreadPool(...)");
        this.backgroundExecutor = executorServiceNewFixedThreadPool3;
        ExecutorService executorServiceNewFixedThreadPool4 = Executors.newFixedThreadPool(1, new PriorityThreadFactory(10, "FrescoLightWeightBackgroundExecutor", true));
        Intrinsics.checkNotNullExpressionValue(executorServiceNewFixedThreadPool4, "newFixedThreadPool(...)");
        this.lightWeightBackgroundExecutor = executorServiceNewFixedThreadPool4;
        ScheduledExecutorService scheduledExecutorServiceNewScheduledThreadPool = Executors.newScheduledThreadPool(i, new PriorityThreadFactory(10, "FrescoBackgroundExecutor", true));
        Intrinsics.checkNotNullExpressionValue(scheduledExecutorServiceNewScheduledThreadPool, "newScheduledThreadPool(...)");
        this.backgroundScheduledExecutorService = scheduledExecutorServiceNewScheduledThreadPool;
    }

    @Override // com.facebook.imagepipeline.core.ExecutorSupplier
    /* renamed from: forLocalStorageRead, reason: from getter */
    public Executor getIoBoundExecutor() {
        return this.ioBoundExecutor;
    }

    @Override // com.facebook.imagepipeline.core.ExecutorSupplier
    public Executor forLocalStorageWrite() {
        return this.ioBoundExecutor;
    }

    @Override // com.facebook.imagepipeline.core.ExecutorSupplier
    /* renamed from: forDecode, reason: from getter */
    public Executor getDecodeExecutor() {
        return this.decodeExecutor;
    }

    @Override // com.facebook.imagepipeline.core.ExecutorSupplier
    /* renamed from: forBackgroundTasks, reason: from getter */
    public Executor getBackgroundExecutor() {
        return this.backgroundExecutor;
    }

    @Override // com.facebook.imagepipeline.core.ExecutorSupplier
    /* renamed from: scheduledExecutorServiceForBackgroundTasks, reason: from getter */
    public ScheduledExecutorService getBackgroundScheduledExecutorService() {
        return this.backgroundScheduledExecutorService;
    }

    @Override // com.facebook.imagepipeline.core.ExecutorSupplier
    /* renamed from: forLightweightBackgroundTasks, reason: from getter */
    public Executor getLightWeightBackgroundExecutor() {
        return this.lightWeightBackgroundExecutor;
    }

    @Override // com.facebook.imagepipeline.core.ExecutorSupplier
    public Executor forThumbnailProducer() {
        return this.ioBoundExecutor;
    }
}
