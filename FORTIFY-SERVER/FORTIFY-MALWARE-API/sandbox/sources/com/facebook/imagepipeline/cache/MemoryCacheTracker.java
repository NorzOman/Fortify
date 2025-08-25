package com.facebook.imagepipeline.cache;

import kotlin.Metadata;

/* compiled from: MemoryCacheTracker.kt */
@Metadata(d1 = {"\u0000\u0014\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0005\bf\u0018\u0000*\u0004\b\u0000\u0010\u00012\u00020\u0002J\u0015\u0010\u0003\u001a\u00020\u00042\u0006\u0010\u0005\u001a\u00028\u0000H&¢\u0006\u0002\u0010\u0006J\u0015\u0010\u0007\u001a\u00020\u00042\u0006\u0010\u0005\u001a\u00028\u0000H&¢\u0006\u0002\u0010\u0006J\u0015\u0010\b\u001a\u00020\u00042\u0006\u0010\u0005\u001a\u00028\u0000H&¢\u0006\u0002\u0010\u0006¨\u0006\t"}, d2 = {"Lcom/facebook/imagepipeline/cache/MemoryCacheTracker;", "K", "", "onCacheHit", "", "cacheKey", "(Ljava/lang/Object;)V", "onCacheMiss", "onCachePut", "imagepipeline_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public interface MemoryCacheTracker<K> {
    void onCacheHit(K cacheKey);

    void onCacheMiss(K cacheKey);

    void onCachePut(K cacheKey);
}
