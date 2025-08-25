package com.facebook.imagepipeline.memory;

import kotlin.Metadata;

/* compiled from: PoolBackend.kt */
@Metadata(d1 = {"\u0000\u001e\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0007\b`\u0018\u0000*\u0004\b\u0000\u0010\u00012\u00020\u0002J\u0018\u0010\u0003\u001a\u0004\u0018\u00018\u00002\u0006\u0010\u0004\u001a\u00020\u0005H¦\u0002¢\u0006\u0002\u0010\u0006J\u0015\u0010\u0007\u001a\u00020\b2\u0006\u0010\t\u001a\u00028\u0000H&¢\u0006\u0002\u0010\nJ\u0015\u0010\u000b\u001a\u00020\u00052\u0006\u0010\t\u001a\u00028\u0000H&¢\u0006\u0002\u0010\fJ\u000f\u0010\r\u001a\u0004\u0018\u00018\u0000H&¢\u0006\u0002\u0010\u000e¨\u0006\u000f"}, d2 = {"Lcom/facebook/imagepipeline/memory/PoolBackend;", "T", "", "get", "size", "", "(I)Ljava/lang/Object;", "put", "", "item", "(Ljava/lang/Object;)V", "getSize", "(Ljava/lang/Object;)I", "pop", "()Ljava/lang/Object;", "imagepipeline_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public interface PoolBackend<T> {
    T get(int size);

    int getSize(T item);

    T pop();

    void put(T item);
}
