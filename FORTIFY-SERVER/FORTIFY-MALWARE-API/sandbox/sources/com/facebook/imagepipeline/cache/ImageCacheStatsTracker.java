package com.facebook.imagepipeline.cache;

import com.facebook.cache.common.CacheKey;
import kotlin.Metadata;

/* compiled from: ImageCacheStatsTracker.kt */
@Metadata(d1 = {"\u0000 \n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\r\n\u0002\u0018\u0002\n\u0002\b\u0003\bf\u0018\u00002\u00020\u0001J\u0010\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u0005H&J\u0010\u0010\u0006\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u0005H&J\u0010\u0010\u0007\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u0005H&J\u0010\u0010\b\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u0005H&J\u0010\u0010\t\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u0005H&J\u0010\u0010\n\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u0005H&J\u0010\u0010\u000b\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u0005H&J\u0010\u0010\f\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u0005H&J\u0010\u0010\r\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u0005H&J\u0010\u0010\u000e\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u0005H&J\u0010\u0010\u000f\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u0005H&J\u0010\u0010\u0010\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u0005H&J\u0018\u0010\u0011\u001a\u00020\u00032\u000e\u0010\u0012\u001a\n\u0012\u0002\b\u0003\u0012\u0002\b\u00030\u0013H&J\u0018\u0010\u0014\u001a\u00020\u00032\u000e\u0010\u0015\u001a\n\u0012\u0002\b\u0003\u0012\u0002\b\u00030\u0013H&¨\u0006\u0016"}, d2 = {"Lcom/facebook/imagepipeline/cache/ImageCacheStatsTracker;", "", "onBitmapCachePut", "", "cacheKey", "Lcom/facebook/cache/common/CacheKey;", "onBitmapCacheHit", "onBitmapCacheMiss", "onMemoryCachePut", "onMemoryCacheHit", "onMemoryCacheMiss", "onStagingAreaHit", "onStagingAreaMiss", "onDiskCacheHit", "onDiskCacheMiss", "onDiskCacheGetFail", "onDiskCachePut", "registerBitmapMemoryCache", "bitmapMemoryCache", "Lcom/facebook/imagepipeline/cache/MemoryCache;", "registerEncodedMemoryCache", "encodedMemoryCache", "imagepipeline_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public interface ImageCacheStatsTracker {
    void onBitmapCacheHit(CacheKey cacheKey);

    void onBitmapCacheMiss(CacheKey cacheKey);

    void onBitmapCachePut(CacheKey cacheKey);

    void onDiskCacheGetFail(CacheKey cacheKey);

    void onDiskCacheHit(CacheKey cacheKey);

    void onDiskCacheMiss(CacheKey cacheKey);

    void onDiskCachePut(CacheKey cacheKey);

    void onMemoryCacheHit(CacheKey cacheKey);

    void onMemoryCacheMiss(CacheKey cacheKey);

    void onMemoryCachePut(CacheKey cacheKey);

    void onStagingAreaHit(CacheKey cacheKey);

    void onStagingAreaMiss(CacheKey cacheKey);

    void registerBitmapMemoryCache(MemoryCache<?, ?> bitmapMemoryCache);

    void registerEncodedMemoryCache(MemoryCache<?, ?> encodedMemoryCache);
}
