package com.facebook.cache.common;

import com.facebook.cache.common.CacheEventListener;
import java.io.IOException;
import javax.annotation.Nullable;

/* loaded from: classes.dex */
public interface CacheEvent {
    @Nullable
    CacheKey getCacheKey();

    long getCacheLimit();

    long getCacheSize();

    @Nullable
    CacheEventListener.EvictionReason getEvictionReason();

    @Nullable
    IOException getException();

    long getItemSize();

    @Nullable
    String getResourceId();
}
