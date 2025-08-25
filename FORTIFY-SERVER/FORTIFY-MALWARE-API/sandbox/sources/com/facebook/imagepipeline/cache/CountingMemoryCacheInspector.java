package com.facebook.imagepipeline.cache;

import android.graphics.Bitmap;
import com.facebook.common.references.CloseableReference;
import com.facebook.imagepipeline.cache.CountingMemoryCache;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: CountingMemoryCacheInspector.kt */
@Metadata(d1 = {"\u0000\u001e\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\u0018\u0000*\u0004\b\u0000\u0010\u0001*\u0004\b\u0001\u0010\u00022\u00020\u0003:\u0002\n\u000bB\u001b\u0012\u0012\u0010\u0004\u001a\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010\u0005¢\u0006\u0004\b\u0006\u0010\u0007J\u0012\u0010\b\u001a\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010\tR\u001a\u0010\u0004\u001a\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010\u0005X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\f"}, d2 = {"Lcom/facebook/imagepipeline/cache/CountingMemoryCacheInspector;", "K", "V", "", "countingBitmapCache", "Lcom/facebook/imagepipeline/cache/CountingMemoryCache;", "<init>", "(Lcom/facebook/imagepipeline/cache/CountingMemoryCache;)V", "dumpCacheContent", "Lcom/facebook/imagepipeline/cache/CountingMemoryCacheInspector$DumpInfo;", "DumpInfoEntry", "DumpInfo", "imagepipeline-base_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class CountingMemoryCacheInspector<K, V> {
    private final CountingMemoryCache<K, V> countingBitmapCache;

    public CountingMemoryCacheInspector(CountingMemoryCache<K, V> countingBitmapCache) {
        Intrinsics.checkNotNullParameter(countingBitmapCache, "countingBitmapCache");
        this.countingBitmapCache = countingBitmapCache;
    }

    /* compiled from: CountingMemoryCacheInspector.kt */
    @Metadata(d1 = {"\u0000\u001e\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010\u0002\n\u0000\u0018\u0000*\u0004\b\u0002\u0010\u0001*\u0004\b\u0003\u0010\u00022\u00020\u0003B\u001f\u0012\u0006\u0010\u0004\u001a\u00028\u0002\u0012\u000e\u0010\u0005\u001a\n\u0012\u0004\u0012\u00028\u0003\u0018\u00010\u0006¢\u0006\u0004\b\u0007\u0010\bJ\u0006\u0010\u000b\u001a\u00020\fR\u0012\u0010\u0004\u001a\u00028\u00028\u0006X\u0087\u0004¢\u0006\u0004\n\u0002\u0010\tR\u0018\u0010\n\u001a\n\u0012\u0004\u0012\u00028\u0003\u0018\u00010\u00068\u0006X\u0087\u0004¢\u0006\u0002\n\u0000¨\u0006\r"}, d2 = {"Lcom/facebook/imagepipeline/cache/CountingMemoryCacheInspector$DumpInfoEntry;", "K", "V", "", "key", "valueRef", "Lcom/facebook/common/references/CloseableReference;", "<init>", "(Ljava/lang/Object;Lcom/facebook/common/references/CloseableReference;)V", "Ljava/lang/Object;", "value", "release", "", "imagepipeline-base_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
    public static final class DumpInfoEntry<K, V> {
        public final K key;
        public final CloseableReference<V> value;

        public DumpInfoEntry(K k, CloseableReference<V> closeableReference) {
            if (k != null) {
                this.key = k;
                this.value = CloseableReference.cloneOrNull(closeableReference);
                return;
            }
            throw new IllegalStateException("Required value was null.".toString());
        }

        public final void release() {
            CloseableReference.closeSafely((CloseableReference<?>) this.value);
        }
    }

    /* compiled from: CountingMemoryCacheInspector.kt */
    @Metadata(d1 = {"\u0000:\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0010!\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010%\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0000\u0018\u0000*\u0004\b\u0002\u0010\u0001*\u0004\b\u0003\u0010\u00022\u00020\u0003B\u001f\u0012\u0006\u0010\u0004\u001a\u00020\u0005\u0012\u0006\u0010\u0006\u001a\u00020\u0005\u0012\u0006\u0010\u0007\u001a\u00020\b¢\u0006\u0004\b\t\u0010\nJ\u0006\u0010\u0015\u001a\u00020\u0016R\u0010\u0010\u000b\u001a\u00020\u00058\u0006X\u0087\u0004¢\u0006\u0002\n\u0000R\u0010\u0010\f\u001a\u00020\u00058\u0006X\u0087\u0004¢\u0006\u0002\n\u0000R\u0010\u0010\r\u001a\u00020\u00058\u0006X\u0087\u0004¢\u0006\u0002\n\u0000R\u0010\u0010\u0004\u001a\u00020\u00058\u0006X\u0087\u0004¢\u0006\u0002\n\u0000R\u0010\u0010\u0006\u001a\u00020\u00058\u0006X\u0087\u0004¢\u0006\u0002\n\u0000R\"\u0010\u000e\u001a\u0014\u0012\u0010\u0012\u000e\u0012\u0004\u0012\u00028\u0002\u0012\u0004\u0012\u00028\u00030\u00100\u000f8\u0006X\u0087\u0004¢\u0006\u0002\n\u0000R\"\u0010\u0011\u001a\u0014\u0012\u0010\u0012\u000e\u0012\u0004\u0012\u00028\u0002\u0012\u0004\u0012\u00028\u00030\u00100\u000f8\u0006X\u0087\u0004¢\u0006\u0002\n\u0000R\u001c\u0010\u0012\u001a\u000e\u0012\u0004\u0012\u00020\u0014\u0012\u0004\u0012\u00020\u00030\u00138\u0006X\u0087\u0004¢\u0006\u0002\n\u0000¨\u0006\u0017"}, d2 = {"Lcom/facebook/imagepipeline/cache/CountingMemoryCacheInspector$DumpInfo;", "K", "V", "", "size", "", "lruSize", "params", "Lcom/facebook/imagepipeline/cache/MemoryCacheParams;", "<init>", "(IILcom/facebook/imagepipeline/cache/MemoryCacheParams;)V", "maxSize", "maxEntriesCount", "maxEntrySize", "lruEntries", "", "Lcom/facebook/imagepipeline/cache/CountingMemoryCacheInspector$DumpInfoEntry;", "sharedEntries", "otherEntries", "", "Landroid/graphics/Bitmap;", "release", "", "imagepipeline-base_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
    public static final class DumpInfo<K, V> {
        public final List<DumpInfoEntry<K, V>> lruEntries;
        public final int lruSize;
        public final int maxEntriesCount;
        public final int maxEntrySize;
        public final int maxSize;
        public final Map<Bitmap, Object> otherEntries;
        public final List<DumpInfoEntry<K, V>> sharedEntries;
        public final int size;

        public DumpInfo(int i, int i2, MemoryCacheParams params) {
            Intrinsics.checkNotNullParameter(params, "params");
            this.maxSize = params.maxCacheSize;
            this.maxEntriesCount = params.maxCacheEntries;
            this.maxEntrySize = params.maxCacheEntrySize;
            this.size = i;
            this.lruSize = i2;
            this.lruEntries = new ArrayList();
            this.sharedEntries = new ArrayList();
            this.otherEntries = new HashMap();
        }

        public final void release() {
            Iterator<DumpInfoEntry<K, V>> it = this.lruEntries.iterator();
            while (it.hasNext()) {
                it.next().release();
            }
            Iterator<DumpInfoEntry<K, V>> it2 = this.sharedEntries.iterator();
            while (it2.hasNext()) {
                it2.next().release();
            }
        }
    }

    public final DumpInfo<K, V> dumpCacheContent() {
        synchronized (this.countingBitmapCache) {
            int sizeInBytes = this.countingBitmapCache.getSizeInBytes();
            int evictionQueueSizeInBytes = this.countingBitmapCache.getEvictionQueueSizeInBytes();
            MemoryCacheParams memoryCacheParams = this.countingBitmapCache.getMemoryCacheParams();
            Intrinsics.checkNotNullExpressionValue(memoryCacheParams, "getMemoryCacheParams(...)");
            DumpInfo<K, V> dumpInfo = new DumpInfo<>(sizeInBytes, evictionQueueSizeInBytes, memoryCacheParams);
            CountingLruMap<K, CountingMemoryCache.Entry<K, V>> cachedEntries = this.countingBitmapCache.getCachedEntries();
            if (cachedEntries == null) {
                return dumpInfo;
            }
            ArrayList<Map.Entry<K, CountingMemoryCache.Entry<K, V>>> matchingEntries = cachedEntries.getMatchingEntries(null);
            Intrinsics.checkNotNullExpressionValue(matchingEntries, "getMatchingEntries(...)");
            Iterator<Map.Entry<K, CountingMemoryCache.Entry<K, V>>> it = matchingEntries.iterator();
            while (it.hasNext()) {
                CountingMemoryCache.Entry<K, V> value = it.next().getValue();
                DumpInfoEntry<K, V> dumpInfoEntry = new DumpInfoEntry<>(value.key, value.valueRef);
                if (value.clientCount > 0) {
                    dumpInfo.sharedEntries.add(dumpInfoEntry);
                } else {
                    dumpInfo.lruEntries.add(dumpInfoEntry);
                }
            }
            Map<Bitmap, Object> otherEntries = this.countingBitmapCache.getOtherEntries();
            if (otherEntries != null) {
                for (Map.Entry<Bitmap, Object> entry : otherEntries.entrySet()) {
                    if (entry != null && !entry.getKey().isRecycled()) {
                        dumpInfo.otherEntries.put(entry.getKey(), entry.getValue());
                    }
                }
            }
            return dumpInfo;
        }
    }
}
