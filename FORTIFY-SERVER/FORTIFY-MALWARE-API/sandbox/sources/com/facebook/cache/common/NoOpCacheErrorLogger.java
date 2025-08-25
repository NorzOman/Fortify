package com.facebook.cache.common;

import com.facebook.cache.common.CacheErrorLogger;
import javax.annotation.Nullable;

/* loaded from: classes.dex */
public class NoOpCacheErrorLogger implements CacheErrorLogger {

    @Nullable
    private static NoOpCacheErrorLogger sInstance;

    @Override // com.facebook.cache.common.CacheErrorLogger
    public void logError(CacheErrorLogger.CacheErrorCategory cacheErrorCategory, Class<?> cls, String str, @Nullable Throwable th) {
    }

    private NoOpCacheErrorLogger() {
    }

    public static synchronized NoOpCacheErrorLogger getInstance() {
        if (sInstance == null) {
            sInstance = new NoOpCacheErrorLogger();
        }
        return sInstance;
    }
}
