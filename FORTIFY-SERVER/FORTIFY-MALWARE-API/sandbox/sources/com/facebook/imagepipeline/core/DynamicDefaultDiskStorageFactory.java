package com.facebook.imagepipeline.core;

import com.facebook.cache.disk.DiskCacheConfig;
import com.facebook.cache.disk.DiskStorage;
import com.facebook.cache.disk.DynamicDefaultDiskStorage;

/* loaded from: classes.dex */
public class DynamicDefaultDiskStorageFactory implements DiskStorageFactory {
    @Override // com.facebook.imagepipeline.core.DiskStorageFactory
    public DiskStorage get(DiskCacheConfig diskCacheConfig) {
        return new DynamicDefaultDiskStorage(diskCacheConfig.getVersion(), diskCacheConfig.getBaseDirectoryPathSupplier(), diskCacheConfig.getBaseDirectoryName(), diskCacheConfig.getCacheErrorLogger());
    }
}
