package com.facebook.react.bridge;

import com.facebook.infer.annotation.Assertions;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: WritableNativeMap.kt */
@Metadata(d1 = {"\u0000L\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u0006\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0010\t\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0003\b\u0007\u0018\u00002\u00020\u00012\u00020\u0002B\u0007¢\u0006\u0004\b\u0003\u0010\u0004J\u0019\u0010\u0005\u001a\u00020\u00062\u0006\u0010\u0007\u001a\u00020\b2\u0006\u0010\t\u001a\u00020\nH\u0096 J\u0019\u0010\u000b\u001a\u00020\u00062\u0006\u0010\u0007\u001a\u00020\b2\u0006\u0010\t\u001a\u00020\fH\u0096 J\u0019\u0010\r\u001a\u00020\u00062\u0006\u0010\u0007\u001a\u00020\b2\u0006\u0010\t\u001a\u00020\u000eH\u0096 J\u0019\u0010\u000f\u001a\u00020\u00062\u0006\u0010\u0007\u001a\u00020\b2\u0006\u0010\t\u001a\u00020\u0010H\u0096 J\u0011\u0010\u0011\u001a\u00020\u00062\u0006\u0010\u0007\u001a\u00020\bH\u0096 J\u001b\u0010\u0012\u001a\u00020\u00062\u0006\u0010\u0007\u001a\u00020\b2\b\u0010\t\u001a\u0004\u0018\u00010\bH\u0096 J\u001a\u0010\u0013\u001a\u00020\u00062\u0006\u0010\u0007\u001a\u00020\b2\b\u0010\t\u001a\u0004\u0018\u00010\u0014H\u0016J\u001a\u0010\u0015\u001a\u00020\u00062\u0006\u0010\u0007\u001a\u00020\b2\b\u0010\t\u001a\u0004\u0018\u00010\u0016H\u0016J\u0010\u0010\u0017\u001a\u00020\u00062\u0006\u0010\u0018\u001a\u00020\u0014H\u0016J\b\u0010\u0019\u001a\u00020\u0002H\u0016J\u001b\u0010\u001a\u001a\u00020\u00062\u0006\u0010\u0007\u001a\u00020\b2\b\u0010\t\u001a\u0004\u0018\u00010\u0001H\u0082 J\u001b\u0010\u001b\u001a\u00020\u00062\u0006\u0010\u0007\u001a\u00020\b2\b\u0010\t\u001a\u0004\u0018\u00010\u001cH\u0082 J\u0011\u0010\u001d\u001a\u00020\u00062\u0006\u0010\u0018\u001a\u00020\u0001H\u0082 J\t\u0010\u001e\u001a\u00020\u0006H\u0082 ¨\u0006\u001f"}, d2 = {"Lcom/facebook/react/bridge/WritableNativeMap;", "Lcom/facebook/react/bridge/ReadableNativeMap;", "Lcom/facebook/react/bridge/WritableMap;", "<init>", "()V", "putBoolean", "", "key", "", "value", "", "putDouble", "", "putInt", "", "putLong", "", "putNull", "putString", "putMap", "Lcom/facebook/react/bridge/ReadableMap;", "putArray", "Lcom/facebook/react/bridge/ReadableArray;", "merge", "source", "copy", "putNativeMap", "putNativeArray", "Lcom/facebook/react/bridge/ReadableNativeArray;", "mergeNativeMap", "initHybrid", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class WritableNativeMap extends ReadableNativeMap implements WritableMap {
    private final native void initHybrid();

    private final native void mergeNativeMap(ReadableNativeMap source);

    private final native void putNativeArray(String key, ReadableNativeArray value);

    private final native void putNativeMap(String key, ReadableNativeMap value);

    @Override // com.facebook.react.bridge.WritableMap
    public native void putBoolean(String key, boolean value);

    @Override // com.facebook.react.bridge.WritableMap
    public native void putDouble(String key, double value);

    @Override // com.facebook.react.bridge.WritableMap
    public native void putInt(String key, int value);

    @Override // com.facebook.react.bridge.WritableMap
    public native void putLong(String key, long value);

    @Override // com.facebook.react.bridge.WritableMap
    public native void putNull(String key);

    @Override // com.facebook.react.bridge.WritableMap
    public native void putString(String key, String value);

    public WritableNativeMap() {
        initHybrid();
    }

    @Override // com.facebook.react.bridge.WritableMap
    public void putMap(String key, ReadableMap value) {
        Intrinsics.checkNotNullParameter(key, "key");
        Assertions.assertCondition(value == null || (value instanceof ReadableNativeMap), "Illegal type provided");
        putNativeMap(key, (ReadableNativeMap) value);
    }

    @Override // com.facebook.react.bridge.WritableMap
    public void putArray(String key, ReadableArray value) {
        Intrinsics.checkNotNullParameter(key, "key");
        Assertions.assertCondition(value == null || (value instanceof ReadableNativeArray), "Illegal type provided");
        putNativeArray(key, (ReadableNativeArray) value);
    }

    @Override // com.facebook.react.bridge.WritableMap
    public void merge(ReadableMap source) {
        Intrinsics.checkNotNullParameter(source, "source");
        Assertions.assertCondition(source instanceof ReadableNativeMap, "Illegal type provided");
        mergeNativeMap((ReadableNativeMap) source);
    }

    @Override // com.facebook.react.bridge.WritableMap
    public WritableMap copy() {
        WritableNativeMap writableNativeMap = new WritableNativeMap();
        writableNativeMap.merge(this);
        return writableNativeMap;
    }
}
