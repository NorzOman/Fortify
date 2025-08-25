package com.facebook.imagepipeline.cache;

import com.facebook.cache.common.HasDebugData;
import com.facebook.common.internal.Predicate;
import com.facebook.common.memory.MemoryTrimType;
import com.facebook.common.memory.MemoryTrimmable;
import com.facebook.common.references.CloseableReference;
import kotlin.Metadata;

/* compiled from: MemoryCache.kt */
@Metadata(d1 = {"\u00006\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\b\b\bf\u0018\u0000*\u0004\b\u0000\u0010\u0001*\u0004\b\u0001\u0010\u00022\u00020\u00032\u00020\u0004:\u0001\u001dJ+\u0010\u0005\u001a\n\u0012\u0004\u0012\u00028\u0001\u0018\u00010\u00062\u0006\u0010\u0007\u001a\u00028\u00002\f\u0010\b\u001a\b\u0012\u0004\u0012\u00028\u00010\u0006H&¢\u0006\u0002\u0010\tJ\u001e\u0010\n\u001a\n\u0012\u0004\u0012\u00028\u0001\u0018\u00010\u00062\u0006\u0010\u0007\u001a\u00028\u0000H¦\u0002¢\u0006\u0002\u0010\u000bJ\u0017\u0010\f\u001a\u0004\u0018\u00018\u00012\u0006\u0010\u0007\u001a\u00028\u0000H&¢\u0006\u0002\u0010\rJ\u0015\u0010\u000e\u001a\u00020\u000f2\u0006\u0010\u0007\u001a\u00028\u0000H&¢\u0006\u0002\u0010\u0010J\u0016\u0010\u0011\u001a\u00020\u00122\f\u0010\u0013\u001a\b\u0012\u0004\u0012\u00028\u00000\u0014H&J\u0017\u0010\u0015\u001a\u00020\u00162\f\u0010\u0013\u001a\b\u0012\u0004\u0012\u00028\u00000\u0014H¦\u0002J\u0016\u0010\u0015\u001a\u00020\u00162\u0006\u0010\u0007\u001a\u00028\u0000H¦\u0002¢\u0006\u0002\u0010\u0017R\u0012\u0010\u0018\u001a\u00020\u0012X¦\u0004¢\u0006\u0006\u001a\u0004\b\u0019\u0010\u001aR\u0012\u0010\u001b\u001a\u00020\u0012X¦\u0004¢\u0006\u0006\u001a\u0004\b\u001c\u0010\u001a¨\u0006\u001e"}, d2 = {"Lcom/facebook/imagepipeline/cache/MemoryCache;", "K", "V", "Lcom/facebook/common/memory/MemoryTrimmable;", "Lcom/facebook/cache/common/HasDebugData;", "cache", "Lcom/facebook/common/references/CloseableReference;", "key", "value", "(Ljava/lang/Object;Lcom/facebook/common/references/CloseableReference;)Lcom/facebook/common/references/CloseableReference;", "get", "(Ljava/lang/Object;)Lcom/facebook/common/references/CloseableReference;", "inspect", "(Ljava/lang/Object;)Ljava/lang/Object;", "probe", "", "(Ljava/lang/Object;)V", "removeAll", "", "predicate", "Lcom/facebook/common/internal/Predicate;", "contains", "", "(Ljava/lang/Object;)Z", "count", "getCount", "()I", "sizeInBytes", "getSizeInBytes", "CacheTrimStrategy", "imagepipeline-base_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public interface MemoryCache<K, V> extends MemoryTrimmable, HasDebugData {

    /* compiled from: MemoryCache.kt */
    @Metadata(d1 = {"\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0006\n\u0000\n\u0002\u0018\u0002\n\u0000\bæ\u0080\u0001\u0018\u00002\u00020\u0001J\u0010\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u0005H&¨\u0006\u0006"}, d2 = {"Lcom/facebook/imagepipeline/cache/MemoryCache$CacheTrimStrategy;", "", "getTrimRatio", "", "trimType", "Lcom/facebook/common/memory/MemoryTrimType;", "imagepipeline-base_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
    public interface CacheTrimStrategy {
        double getTrimRatio(MemoryTrimType trimType);
    }

    CloseableReference<V> cache(K key, CloseableReference<V> value);

    boolean contains(Predicate<K> predicate);

    boolean contains(K key);

    CloseableReference<V> get(K key);

    int getCount();

    int getSizeInBytes();

    V inspect(K key);

    void probe(K key);

    int removeAll(Predicate<K> predicate);
}
