package com.facebook.react.bridge;

import java.util.Iterator;
import java.util.Map;
import kotlin.Metadata;
import kotlin.jvm.internal.markers.KMappedMarker;

/* compiled from: ReadableNativeMap.kt */
@Metadata(d1 = {"\u0000'\n\u0000\n\u0002\u0010(\n\u0002\u0010&\n\u0002\u0010\u000e\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\b\n\u0002\b\u0005\n\u0002\u0010\u000b\n\u0002\b\u0002*\u0001\u0000\b\n\u0018\u00002\u0014\u0012\u0010\u0012\u000e\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u00040\u00020\u0001J\t\u0010\u000b\u001a\u00020\fH\u0096\u0002J\u0015\u0010\r\u001a\u000e\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u00040\u0002H\u0096\u0002R\u001a\u0010\u0005\u001a\u00020\u0006X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0007\u0010\b\"\u0004\b\t\u0010\n¨\u0006\u000e"}, d2 = {"com/facebook/react/bridge/ReadableNativeMap$entryIterator$1$1", "", "", "", "", "currentIndex", "", "getCurrentIndex", "()I", "setCurrentIndex", "(I)V", "hasNext", "", "next", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class ReadableNativeMap$entryIterator$1$1 implements Iterator<Map.Entry<? extends String, ? extends Object>>, KMappedMarker {
    final /* synthetic */ String[] $iteratorKeys;
    final /* synthetic */ Object[] $iteratorValues;
    private int currentIndex;

    @Override // java.util.Iterator
    public void remove() {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }

    ReadableNativeMap$entryIterator$1$1(String[] strArr, Object[] objArr) {
        this.$iteratorKeys = strArr;
        this.$iteratorValues = objArr;
    }

    public final int getCurrentIndex() {
        return this.currentIndex;
    }

    public final void setCurrentIndex(int i) {
        this.currentIndex = i;
    }

    @Override // java.util.Iterator
    public boolean hasNext() {
        return this.currentIndex < this.$iteratorKeys.length;
    }

    @Override // java.util.Iterator
    public Map.Entry<? extends String, ? extends Object> next() {
        int i = this.currentIndex;
        this.currentIndex = i + 1;
        return new ReadableNativeMap$entryIterator$1$1$next$1(this.$iteratorKeys, i, this.$iteratorValues);
    }
}
