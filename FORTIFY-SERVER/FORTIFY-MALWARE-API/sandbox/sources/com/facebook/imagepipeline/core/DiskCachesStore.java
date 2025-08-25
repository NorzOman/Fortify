package com.facebook.imagepipeline.core;

import com.facebook.cache.disk.FileCache;
import com.facebook.common.internal.ImmutableMap;
import com.facebook.imagepipeline.cache.BufferedDiskCache;
import java.util.Map;
import kotlin.Metadata;

/* compiled from: DiskCachesStore.kt */
@Metadata(d1 = {"\u0000.\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0010$\n\u0002\u0010\u000e\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\bf\u0018\u00002\u00020\u0001R\u0012\u0010\u0002\u001a\u00020\u0003X¦\u0004¢\u0006\u0006\u001a\u0004\b\u0004\u0010\u0005R\u0012\u0010\u0006\u001a\u00020\u0007X¦\u0004¢\u0006\u0006\u001a\u0004\b\b\u0010\tR\u0012\u0010\n\u001a\u00020\u0003X¦\u0004¢\u0006\u0006\u001a\u0004\b\u000b\u0010\u0005R\u0012\u0010\f\u001a\u00020\u0007X¦\u0004¢\u0006\u0006\u001a\u0004\b\r\u0010\tR\u001e\u0010\u000e\u001a\u000e\u0012\u0004\u0012\u00020\u0010\u0012\u0004\u0012\u00020\u00030\u000fX¦\u0004¢\u0006\u0006\u001a\u0004\b\u0011\u0010\u0012R\u001e\u0010\u0013\u001a\u000e\u0012\u0004\u0012\u00020\u0010\u0012\u0004\u0012\u00020\u00070\u0014X¦\u0004¢\u0006\u0006\u001a\u0004\b\u0015\u0010\u0016¨\u0006\u0017"}, d2 = {"Lcom/facebook/imagepipeline/core/DiskCachesStore;", "", "mainFileCache", "Lcom/facebook/cache/disk/FileCache;", "getMainFileCache", "()Lcom/facebook/cache/disk/FileCache;", "mainBufferedDiskCache", "Lcom/facebook/imagepipeline/cache/BufferedDiskCache;", "getMainBufferedDiskCache", "()Lcom/facebook/imagepipeline/cache/BufferedDiskCache;", "smallImageFileCache", "getSmallImageFileCache", "smallImageBufferedDiskCache", "getSmallImageBufferedDiskCache", "dynamicFileCaches", "", "", "getDynamicFileCaches", "()Ljava/util/Map;", "dynamicBufferedDiskCaches", "Lcom/facebook/common/internal/ImmutableMap;", "getDynamicBufferedDiskCaches", "()Lcom/facebook/common/internal/ImmutableMap;", "imagepipeline_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public interface DiskCachesStore {
    ImmutableMap<String, BufferedDiskCache> getDynamicBufferedDiskCaches();

    Map<String, FileCache> getDynamicFileCaches();

    BufferedDiskCache getMainBufferedDiskCache();

    FileCache getMainFileCache();

    BufferedDiskCache getSmallImageBufferedDiskCache();

    FileCache getSmallImageFileCache();
}
