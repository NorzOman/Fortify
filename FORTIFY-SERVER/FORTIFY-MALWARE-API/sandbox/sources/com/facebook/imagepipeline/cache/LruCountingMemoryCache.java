package com.facebook.imagepipeline.cache;

import android.graphics.Bitmap;
import android.os.SystemClock;
import com.facebook.cache.common.HasDebugData;
import com.facebook.common.internal.Objects;
import com.facebook.common.internal.Preconditions;
import com.facebook.common.internal.Predicate;
import com.facebook.common.internal.Supplier;
import com.facebook.common.memory.MemoryTrimType;
import com.facebook.common.references.CloseableReference;
import com.facebook.common.references.ResourceReleaser;
import com.facebook.imagepipeline.cache.CountingMemoryCache;
import com.facebook.imagepipeline.cache.MemoryCache;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Map;
import java.util.WeakHashMap;
import javax.annotation.Nullable;

/* loaded from: classes.dex */
public class LruCountingMemoryCache<K, V> implements CountingMemoryCache<K, V>, MemoryCache<K, V>, HasDebugData {
    private final MemoryCache.CacheTrimStrategy mCacheTrimStrategy;
    final CountingLruMap<K, CountingMemoryCache.Entry<K, V>> mCachedEntries;

    @Nullable
    private final CountingMemoryCache.EntryStateObserver<K> mEntryStateObserver;
    final CountingLruMap<K, CountingMemoryCache.Entry<K, V>> mExclusiveEntries;
    private final boolean mIgnoreSizeMismatch;
    protected MemoryCacheParams mMemoryCacheParams;
    private final Supplier<MemoryCacheParams> mMemoryCacheParamsSupplier;
    private final boolean mStoreEntrySize;
    private final ValueDescriptor<V> mValueDescriptor;
    final Map<Bitmap, Object> mOtherEntries = new WeakHashMap();
    private long mLastCacheParamsCheck = SystemClock.uptimeMillis();

    public LruCountingMemoryCache(ValueDescriptor<V> valueDescriptor, MemoryCache.CacheTrimStrategy cacheTrimStrategy, Supplier<MemoryCacheParams> supplier, @Nullable CountingMemoryCache.EntryStateObserver<K> entryStateObserver, boolean z, boolean z2) {
        this.mValueDescriptor = valueDescriptor;
        this.mExclusiveEntries = new CountingLruMap<>(wrapValueDescriptor(valueDescriptor));
        this.mCachedEntries = new CountingLruMap<>(wrapValueDescriptor(valueDescriptor));
        this.mCacheTrimStrategy = cacheTrimStrategy;
        this.mMemoryCacheParamsSupplier = supplier;
        this.mMemoryCacheParams = (MemoryCacheParams) Preconditions.checkNotNull(supplier.get(), "mMemoryCacheParamsSupplier returned null");
        this.mEntryStateObserver = entryStateObserver;
        this.mStoreEntrySize = z;
        this.mIgnoreSizeMismatch = z2;
    }

    private ValueDescriptor<CountingMemoryCache.Entry<K, V>> wrapValueDescriptor(final ValueDescriptor<V> valueDescriptor) {
        return new ValueDescriptor<CountingMemoryCache.Entry<K, V>>() { // from class: com.facebook.imagepipeline.cache.LruCountingMemoryCache.1
            @Override // com.facebook.imagepipeline.cache.ValueDescriptor
            public int getSizeInBytes(CountingMemoryCache.Entry<K, V> entry) {
                if (LruCountingMemoryCache.this.mStoreEntrySize) {
                    return entry.size;
                }
                return valueDescriptor.getSizeInBytes(entry.valueRef.get());
            }
        };
    }

    @Override // com.facebook.imagepipeline.cache.MemoryCache
    @Nullable
    public CloseableReference<V> cache(K k, CloseableReference<V> closeableReference) {
        return cache(k, closeableReference, this.mEntryStateObserver);
    }

    @Override // com.facebook.imagepipeline.cache.CountingMemoryCache
    @Nullable
    public CloseableReference<V> cache(K k, CloseableReference<V> closeableReference, @Nullable CountingMemoryCache.EntryStateObserver<K> entryStateObserver) {
        CountingMemoryCache.Entry<K, V> entryRemove;
        CloseableReference<V> closeableReferenceNewClientReference;
        CloseableReference<V> closeableReferenceReferenceToClose;
        CountingMemoryCache.Entry<K, V> entryOf;
        Preconditions.checkNotNull(k);
        Preconditions.checkNotNull(closeableReference);
        maybeUpdateCacheParams();
        synchronized (this) {
            entryRemove = this.mExclusiveEntries.remove(k);
            CountingMemoryCache.Entry<K, V> entryRemove2 = this.mCachedEntries.remove(k);
            closeableReferenceNewClientReference = null;
            if (entryRemove2 != null) {
                makeOrphan(entryRemove2);
                closeableReferenceReferenceToClose = referenceToClose(entryRemove2);
            } else {
                closeableReferenceReferenceToClose = null;
            }
            int sizeInBytes = this.mValueDescriptor.getSizeInBytes(closeableReference.get());
            if (canCacheNewValueOfSize(sizeInBytes)) {
                if (this.mStoreEntrySize) {
                    entryOf = CountingMemoryCache.Entry.of(k, closeableReference, sizeInBytes, entryStateObserver);
                } else {
                    entryOf = CountingMemoryCache.Entry.of(k, closeableReference, entryStateObserver);
                }
                this.mCachedEntries.put(k, entryOf);
                closeableReferenceNewClientReference = newClientReference(entryOf);
            }
        }
        CloseableReference.closeSafely((CloseableReference<?>) closeableReferenceReferenceToClose);
        maybeNotifyExclusiveEntryRemoval(entryRemove);
        maybeEvictEntries();
        return closeableReferenceNewClientReference;
    }

    /* JADX WARN: Removed duplicated region for block: B:11:0x001f  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private synchronized boolean canCacheNewValueOfSize(int r4) {
        /*
            r3 = this;
            monitor-enter(r3)
            com.facebook.imagepipeline.cache.MemoryCacheParams r0 = r3.mMemoryCacheParams     // Catch: java.lang.Throwable -> L22
            int r0 = r0.maxCacheEntrySize     // Catch: java.lang.Throwable -> L22
            if (r4 > r0) goto L1f
            int r0 = r3.getInUseCount()     // Catch: java.lang.Throwable -> L22
            com.facebook.imagepipeline.cache.MemoryCacheParams r1 = r3.mMemoryCacheParams     // Catch: java.lang.Throwable -> L22
            int r1 = r1.maxCacheEntries     // Catch: java.lang.Throwable -> L22
            r2 = 1
            int r1 = r1 - r2
            if (r0 > r1) goto L1f
            int r0 = r3.getInUseSizeInBytes()     // Catch: java.lang.Throwable -> L22
            com.facebook.imagepipeline.cache.MemoryCacheParams r1 = r3.mMemoryCacheParams     // Catch: java.lang.Throwable -> L22
            int r1 = r1.maxCacheSize     // Catch: java.lang.Throwable -> L22
            int r1 = r1 - r4
            if (r0 > r1) goto L1f
            goto L20
        L1f:
            r2 = 0
        L20:
            monitor-exit(r3)
            return r2
        L22:
            r4 = move-exception
            monitor-exit(r3)     // Catch: java.lang.Throwable -> L22
            throw r4
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.imagepipeline.cache.LruCountingMemoryCache.canCacheNewValueOfSize(int):boolean");
    }

    @Override // com.facebook.imagepipeline.cache.MemoryCache
    @Nullable
    public CloseableReference<V> get(K k) {
        CountingMemoryCache.Entry<K, V> entryRemove;
        CloseableReference<V> closeableReferenceNewClientReference;
        Preconditions.checkNotNull(k);
        synchronized (this) {
            entryRemove = this.mExclusiveEntries.remove(k);
            CountingMemoryCache.Entry<K, V> entry = this.mCachedEntries.get(k);
            closeableReferenceNewClientReference = entry != null ? newClientReference(entry) : null;
        }
        maybeNotifyExclusiveEntryRemoval(entryRemove);
        maybeUpdateCacheParams();
        maybeEvictEntries();
        return closeableReferenceNewClientReference;
    }

    @Override // com.facebook.imagepipeline.cache.MemoryCache
    @Nullable
    public synchronized V inspect(K k) {
        CountingMemoryCache.Entry<K, V> entry = this.mCachedEntries.get(k);
        if (entry == null) {
            return null;
        }
        return entry.valueRef.get();
    }

    @Override // com.facebook.imagepipeline.cache.MemoryCache
    public void probe(K k) {
        Preconditions.checkNotNull(k);
        synchronized (this) {
            CountingMemoryCache.Entry<K, V> entryRemove = this.mExclusiveEntries.remove(k);
            if (entryRemove != null) {
                this.mExclusiveEntries.put(k, entryRemove);
            }
        }
    }

    private synchronized CloseableReference<V> newClientReference(final CountingMemoryCache.Entry<K, V> entry) {
        increaseClientCount(entry);
        return CloseableReference.of(entry.valueRef.get(), new ResourceReleaser<V>() { // from class: com.facebook.imagepipeline.cache.LruCountingMemoryCache.2
            @Override // com.facebook.common.references.ResourceReleaser
            public void release(V v) {
                LruCountingMemoryCache.this.releaseClientReference(entry);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void releaseClientReference(CountingMemoryCache.Entry<K, V> entry) {
        boolean zMaybeAddToExclusives;
        CloseableReference<V> closeableReferenceReferenceToClose;
        Preconditions.checkNotNull(entry);
        synchronized (this) {
            decreaseClientCount(entry);
            zMaybeAddToExclusives = maybeAddToExclusives(entry);
            closeableReferenceReferenceToClose = referenceToClose(entry);
        }
        CloseableReference.closeSafely((CloseableReference<?>) closeableReferenceReferenceToClose);
        if (!zMaybeAddToExclusives) {
            entry = null;
        }
        maybeNotifyExclusiveEntryInsertion(entry);
        maybeUpdateCacheParams();
        maybeEvictEntries();
    }

    private synchronized boolean maybeAddToExclusives(CountingMemoryCache.Entry<K, V> entry) {
        if (entry.isOrphan || entry.clientCount != 0) {
            return false;
        }
        this.mExclusiveEntries.put(entry.key, entry);
        return true;
    }

    @Override // com.facebook.imagepipeline.cache.CountingMemoryCache
    @Nullable
    public CloseableReference<V> reuse(K k) {
        CountingMemoryCache.Entry<K, V> entryRemove;
        boolean z;
        CloseableReference<V> closeableReference;
        Preconditions.checkNotNull(k);
        synchronized (this) {
            entryRemove = this.mExclusiveEntries.remove(k);
            if (entryRemove != null) {
                CountingMemoryCache.Entry<K, V> entryRemove2 = this.mCachedEntries.remove(k);
                Preconditions.checkNotNull(entryRemove2);
                Preconditions.checkState(entryRemove2.clientCount == 0);
                closeableReference = entryRemove2.valueRef;
                z = true;
            } else {
                closeableReference = null;
            }
        }
        if (z) {
            maybeNotifyExclusiveEntryRemoval(entryRemove);
        }
        return closeableReference;
    }

    @Override // com.facebook.imagepipeline.cache.MemoryCache
    public int removeAll(Predicate<K> predicate) {
        ArrayList<CountingMemoryCache.Entry<K, V>> arrayListRemoveAll;
        ArrayList<CountingMemoryCache.Entry<K, V>> arrayListRemoveAll2;
        synchronized (this) {
            arrayListRemoveAll = this.mExclusiveEntries.removeAll(predicate);
            arrayListRemoveAll2 = this.mCachedEntries.removeAll(predicate);
            makeOrphans(arrayListRemoveAll2);
        }
        maybeClose(arrayListRemoveAll2);
        maybeNotifyExclusiveEntryRemoval(arrayListRemoveAll);
        maybeUpdateCacheParams();
        maybeEvictEntries();
        return arrayListRemoveAll2.size();
    }

    @Override // com.facebook.imagepipeline.cache.CountingMemoryCache
    public void clear() {
        ArrayList<CountingMemoryCache.Entry<K, V>> arrayListClear;
        ArrayList<CountingMemoryCache.Entry<K, V>> arrayListClear2;
        synchronized (this) {
            arrayListClear = this.mExclusiveEntries.clear();
            arrayListClear2 = this.mCachedEntries.clear();
            makeOrphans(arrayListClear2);
        }
        maybeClose(arrayListClear2);
        maybeNotifyExclusiveEntryRemoval(arrayListClear);
        maybeUpdateCacheParams();
    }

    @Override // com.facebook.imagepipeline.cache.MemoryCache
    public synchronized boolean contains(Predicate<K> predicate) {
        return !this.mCachedEntries.getMatchingEntries(predicate).isEmpty();
    }

    @Override // com.facebook.imagepipeline.cache.MemoryCache
    public synchronized boolean contains(K k) {
        return this.mCachedEntries.contains(k);
    }

    @Override // com.facebook.common.memory.MemoryTrimmable
    public void trim(MemoryTrimType memoryTrimType) {
        ArrayList<CountingMemoryCache.Entry<K, V>> arrayListTrimExclusivelyOwnedEntries;
        double trimRatio = this.mCacheTrimStrategy.getTrimRatio(memoryTrimType);
        synchronized (this) {
            arrayListTrimExclusivelyOwnedEntries = trimExclusivelyOwnedEntries(Integer.MAX_VALUE, Math.max(0, ((int) (this.mCachedEntries.getSizeInBytes() * (1.0d - trimRatio))) - getInUseSizeInBytes()));
            makeOrphans(arrayListTrimExclusivelyOwnedEntries);
        }
        maybeClose(arrayListTrimExclusivelyOwnedEntries);
        maybeNotifyExclusiveEntryRemoval(arrayListTrimExclusivelyOwnedEntries);
        maybeUpdateCacheParams();
        maybeEvictEntries();
    }

    private synchronized void maybeUpdateCacheParams() {
        if (this.mLastCacheParamsCheck + this.mMemoryCacheParams.paramsCheckIntervalMs > SystemClock.uptimeMillis()) {
            return;
        }
        this.mLastCacheParamsCheck = SystemClock.uptimeMillis();
        this.mMemoryCacheParams = (MemoryCacheParams) Preconditions.checkNotNull(this.mMemoryCacheParamsSupplier.get(), "mMemoryCacheParamsSupplier returned null");
    }

    @Override // com.facebook.imagepipeline.cache.CountingMemoryCache
    public MemoryCacheParams getMemoryCacheParams() {
        return this.mMemoryCacheParams;
    }

    @Override // com.facebook.imagepipeline.cache.CountingMemoryCache
    public CountingLruMap<K, CountingMemoryCache.Entry<K, V>> getCachedEntries() {
        return this.mCachedEntries;
    }

    @Override // com.facebook.imagepipeline.cache.CountingMemoryCache
    public Map<Bitmap, Object> getOtherEntries() {
        return this.mOtherEntries;
    }

    @Override // com.facebook.imagepipeline.cache.CountingMemoryCache
    public void maybeEvictEntries() {
        ArrayList<CountingMemoryCache.Entry<K, V>> arrayListTrimExclusivelyOwnedEntries;
        synchronized (this) {
            arrayListTrimExclusivelyOwnedEntries = trimExclusivelyOwnedEntries(Math.min(this.mMemoryCacheParams.maxEvictionQueueEntries, this.mMemoryCacheParams.maxCacheEntries - getInUseCount()), Math.min(this.mMemoryCacheParams.maxEvictionQueueSize, this.mMemoryCacheParams.maxCacheSize - getInUseSizeInBytes()));
            makeOrphans(arrayListTrimExclusivelyOwnedEntries);
        }
        maybeClose(arrayListTrimExclusivelyOwnedEntries);
        maybeNotifyExclusiveEntryRemoval(arrayListTrimExclusivelyOwnedEntries);
    }

    @Nullable
    private synchronized ArrayList<CountingMemoryCache.Entry<K, V>> trimExclusivelyOwnedEntries(int i, int i2) {
        int iMax = Math.max(i, 0);
        int iMax2 = Math.max(i2, 0);
        if (this.mExclusiveEntries.getCount() <= iMax && this.mExclusiveEntries.getSizeInBytes() <= iMax2) {
            return null;
        }
        ArrayList<CountingMemoryCache.Entry<K, V>> arrayList = new ArrayList<>();
        while (true) {
            if (this.mExclusiveEntries.getCount() <= iMax && this.mExclusiveEntries.getSizeInBytes() <= iMax2) {
                break;
            }
            K firstKey = this.mExclusiveEntries.getFirstKey();
            if (firstKey == null) {
                if (this.mIgnoreSizeMismatch) {
                    this.mExclusiveEntries.resetSize();
                } else {
                    throw new IllegalStateException(String.format("key is null, but exclusiveEntries count: %d, size: %d", Integer.valueOf(this.mExclusiveEntries.getCount()), Integer.valueOf(this.mExclusiveEntries.getSizeInBytes())));
                }
            } else {
                this.mExclusiveEntries.remove(firstKey);
                arrayList.add(this.mCachedEntries.remove(firstKey));
            }
        }
        return arrayList;
    }

    private void maybeClose(@Nullable ArrayList<CountingMemoryCache.Entry<K, V>> arrayList) {
        if (arrayList != null) {
            Iterator<CountingMemoryCache.Entry<K, V>> it = arrayList.iterator();
            while (it.hasNext()) {
                CloseableReference.closeSafely((CloseableReference<?>) referenceToClose(it.next()));
            }
        }
    }

    private void maybeNotifyExclusiveEntryRemoval(@Nullable ArrayList<CountingMemoryCache.Entry<K, V>> arrayList) {
        if (arrayList != null) {
            Iterator<CountingMemoryCache.Entry<K, V>> it = arrayList.iterator();
            while (it.hasNext()) {
                maybeNotifyExclusiveEntryRemoval(it.next());
            }
        }
    }

    private static <K, V> void maybeNotifyExclusiveEntryRemoval(@Nullable CountingMemoryCache.Entry<K, V> entry) {
        if (entry == null || entry.observer == null) {
            return;
        }
        entry.observer.onExclusivityChanged(entry.key, false);
    }

    private static <K, V> void maybeNotifyExclusiveEntryInsertion(@Nullable CountingMemoryCache.Entry<K, V> entry) {
        if (entry == null || entry.observer == null) {
            return;
        }
        entry.observer.onExclusivityChanged(entry.key, true);
    }

    private synchronized void makeOrphans(@Nullable ArrayList<CountingMemoryCache.Entry<K, V>> arrayList) {
        if (arrayList != null) {
            Iterator<CountingMemoryCache.Entry<K, V>> it = arrayList.iterator();
            while (it.hasNext()) {
                makeOrphan(it.next());
            }
        }
    }

    private synchronized void makeOrphan(CountingMemoryCache.Entry<K, V> entry) {
        Preconditions.checkNotNull(entry);
        Preconditions.checkState(!entry.isOrphan);
        entry.isOrphan = true;
    }

    private synchronized void increaseClientCount(CountingMemoryCache.Entry<K, V> entry) {
        Preconditions.checkNotNull(entry);
        Preconditions.checkState(!entry.isOrphan);
        entry.clientCount++;
    }

    private synchronized void decreaseClientCount(CountingMemoryCache.Entry<K, V> entry) {
        Preconditions.checkNotNull(entry);
        Preconditions.checkState(entry.clientCount > 0);
        entry.clientCount--;
    }

    @Nullable
    private synchronized CloseableReference<V> referenceToClose(CountingMemoryCache.Entry<K, V> entry) {
        Preconditions.checkNotNull(entry);
        return (entry.isOrphan && entry.clientCount == 0) ? entry.valueRef : null;
    }

    @Override // com.facebook.imagepipeline.cache.MemoryCache
    public synchronized int getCount() {
        return this.mCachedEntries.getCount();
    }

    @Override // com.facebook.imagepipeline.cache.MemoryCache
    public synchronized int getSizeInBytes() {
        return this.mCachedEntries.getSizeInBytes();
    }

    public synchronized int getInUseCount() {
        return this.mCachedEntries.getCount() - this.mExclusiveEntries.getCount();
    }

    @Override // com.facebook.imagepipeline.cache.CountingMemoryCache
    public synchronized int getInUseSizeInBytes() {
        return this.mCachedEntries.getSizeInBytes() - this.mExclusiveEntries.getSizeInBytes();
    }

    @Override // com.facebook.imagepipeline.cache.CountingMemoryCache
    public synchronized int getEvictionQueueCount() {
        return this.mExclusiveEntries.getCount();
    }

    @Override // com.facebook.imagepipeline.cache.CountingMemoryCache
    public synchronized int getEvictionQueueSizeInBytes() {
        return this.mExclusiveEntries.getSizeInBytes();
    }

    @Override // com.facebook.cache.common.HasDebugData
    @Nullable
    public synchronized String getDebugData() {
        return Objects.toStringHelper("CountingMemoryCache").add("cached_entries_count", this.mCachedEntries.getCount()).add("cached_entries_size_bytes", this.mCachedEntries.getSizeInBytes()).add("exclusive_entries_count", this.mExclusiveEntries.getCount()).add("exclusive_entries_size_bytes", this.mExclusiveEntries.getSizeInBytes()).toString();
    }
}
