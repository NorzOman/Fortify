package com.facebook.imagepipeline.cache;

import com.facebook.cache.common.CacheKey;
import com.facebook.common.internal.Preconditions;
import com.facebook.common.logging.FLog;
import com.facebook.common.memory.PooledByteBuffer;
import com.facebook.common.references.CloseableReference;
import com.facebook.imagepipeline.image.EncodedImage;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import javax.annotation.Nullable;

/* loaded from: classes.dex */
public class StagingArea {
    private static final Class<?> TAG = StagingArea.class;
    private Map<CacheKey, EncodedImage> mMap = new HashMap();

    private StagingArea() {
    }

    public static StagingArea getInstance() {
        return new StagingArea();
    }

    public synchronized void put(CacheKey cacheKey, EncodedImage encodedImage) {
        Preconditions.checkNotNull(cacheKey);
        Preconditions.checkArgument(Boolean.valueOf(EncodedImage.isValid(encodedImage)));
        EncodedImage.closeSafely(this.mMap.put(cacheKey, EncodedImage.cloneOrNull(encodedImage)));
        logStats();
    }

    public void clearAll() {
        ArrayList arrayList;
        synchronized (this) {
            arrayList = new ArrayList(this.mMap.values());
            this.mMap.clear();
        }
        for (int i = 0; i < arrayList.size(); i++) {
            EncodedImage encodedImage = (EncodedImage) arrayList.get(i);
            if (encodedImage != null) {
                encodedImage.close();
            }
        }
    }

    public boolean remove(CacheKey cacheKey) {
        EncodedImage encodedImageRemove;
        Preconditions.checkNotNull(cacheKey);
        synchronized (this) {
            encodedImageRemove = this.mMap.remove(cacheKey);
        }
        if (encodedImageRemove == null) {
            return false;
        }
        try {
            return encodedImageRemove.isValid();
        } finally {
            encodedImageRemove.close();
        }
    }

    public synchronized boolean remove(CacheKey cacheKey, EncodedImage encodedImage) {
        Preconditions.checkNotNull(cacheKey);
        Preconditions.checkNotNull(encodedImage);
        Preconditions.checkArgument(Boolean.valueOf(EncodedImage.isValid(encodedImage)));
        EncodedImage encodedImage2 = this.mMap.get(cacheKey);
        if (encodedImage2 == null) {
            return false;
        }
        CloseableReference<PooledByteBuffer> byteBufferRef = encodedImage2.getByteBufferRef();
        CloseableReference<PooledByteBuffer> byteBufferRef2 = encodedImage.getByteBufferRef();
        if (byteBufferRef != null && byteBufferRef2 != null) {
            try {
                if (byteBufferRef.get() == byteBufferRef2.get()) {
                    this.mMap.remove(cacheKey);
                    CloseableReference.closeSafely(byteBufferRef2);
                    CloseableReference.closeSafely(byteBufferRef);
                    EncodedImage.closeSafely(encodedImage2);
                    logStats();
                    return true;
                }
            } finally {
                CloseableReference.closeSafely(byteBufferRef2);
                CloseableReference.closeSafely(byteBufferRef);
                EncodedImage.closeSafely(encodedImage2);
            }
        }
        return false;
    }

    @Nullable
    public synchronized EncodedImage get(CacheKey cacheKey) {
        Preconditions.checkNotNull(cacheKey);
        EncodedImage encodedImageCloneOrNull = this.mMap.get(cacheKey);
        if (encodedImageCloneOrNull != null) {
            synchronized (encodedImageCloneOrNull) {
                if (!EncodedImage.isValid(encodedImageCloneOrNull)) {
                    this.mMap.remove(cacheKey);
                    FLog.w(TAG, "Found closed reference %d for key %s (%d)", Integer.valueOf(System.identityHashCode(encodedImageCloneOrNull)), cacheKey.getUriString(), Integer.valueOf(System.identityHashCode(cacheKey)));
                    return null;
                }
                encodedImageCloneOrNull = EncodedImage.cloneOrNull(encodedImageCloneOrNull);
            }
        }
        return encodedImageCloneOrNull;
    }

    public synchronized boolean containsKey(CacheKey cacheKey) {
        Preconditions.checkNotNull(cacheKey);
        if (!this.mMap.containsKey(cacheKey)) {
            return false;
        }
        EncodedImage encodedImage = this.mMap.get(cacheKey);
        synchronized (encodedImage) {
            if (EncodedImage.isValid(encodedImage)) {
                return true;
            }
            this.mMap.remove(cacheKey);
            FLog.w(TAG, "Found closed reference %d for key %s (%d)", Integer.valueOf(System.identityHashCode(encodedImage)), cacheKey.getUriString(), Integer.valueOf(System.identityHashCode(cacheKey)));
            return false;
        }
    }

    private synchronized void logStats() {
        FLog.v(TAG, "Count = %d", Integer.valueOf(this.mMap.size()));
    }
}
