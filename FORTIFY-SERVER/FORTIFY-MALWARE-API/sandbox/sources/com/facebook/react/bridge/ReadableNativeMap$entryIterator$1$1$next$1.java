package com.facebook.react.bridge;

import java.util.Map;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.markers.KMutableMap;

/* compiled from: ReadableNativeMap.kt */
@Metadata(d1 = {"\u0000\u0015\n\u0000\n\u0002\u0010'\n\u0002\u0010\u000e\n\u0002\u0010\u0000\n\u0002\b\t*\u0001\u0000\b\n\u0018\u00002\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00030\u0001J\u0010\u0010\n\u001a\u00020\u00032\u0006\u0010\u000b\u001a\u00020\u0003H\u0016R\u0014\u0010\u0004\u001a\u00020\u00028VX\u0096\u0004¢\u0006\u0006\u001a\u0004\b\u0005\u0010\u0006R\u0014\u0010\u0007\u001a\u00020\u00038VX\u0096\u0004¢\u0006\u0006\u001a\u0004\b\b\u0010\t¨\u0006\f"}, d2 = {"com/facebook/react/bridge/ReadableNativeMap$entryIterator$1$1$next$1", "", "", "", "key", "getKey", "()Ljava/lang/String;", "value", "getValue", "()Ljava/lang/Object;", "setValue", "newValue", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class ReadableNativeMap$entryIterator$1$1$next$1 implements Map.Entry<String, Object>, KMutableMap.Entry {
    final /* synthetic */ int $index;
    final /* synthetic */ String[] $iteratorKeys;
    final /* synthetic */ Object[] $iteratorValues;

    ReadableNativeMap$entryIterator$1$1$next$1(String[] strArr, int i, Object[] objArr) {
        this.$iteratorKeys = strArr;
        this.$index = i;
        this.$iteratorValues = objArr;
    }

    @Override // java.util.Map.Entry
    public String getKey() {
        return this.$iteratorKeys[this.$index];
    }

    @Override // java.util.Map.Entry
    public Object getValue() {
        return this.$iteratorValues[this.$index];
    }

    @Override // java.util.Map.Entry
    public Object setValue(Object newValue) {
        Intrinsics.checkNotNullParameter(newValue, "newValue");
        throw new UnsupportedOperationException("Can't set a value while iterating over a ReadableNativeMap");
    }
}
