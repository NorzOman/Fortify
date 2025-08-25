package com.facebook.react.bridge;

import kotlin.Metadata;

/* compiled from: WritableNativeArray.kt */
@Metadata(d1 = {"\u0000N\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u0006\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0010\t\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\b\u0007\u0018\u00002\u00020\u00012\u00020\u0002B\u0007¢\u0006\u0004\b\u0003\u0010\u0004J\t\u0010\u0005\u001a\u00020\u0006H\u0096 J\u0011\u0010\u0007\u001a\u00020\u00062\u0006\u0010\b\u001a\u00020\tH\u0096 J\u0011\u0010\n\u001a\u00020\u00062\u0006\u0010\b\u001a\u00020\u000bH\u0096 J\u0011\u0010\f\u001a\u00020\u00062\u0006\u0010\b\u001a\u00020\rH\u0096 J\u0011\u0010\u000e\u001a\u00020\u00062\u0006\u0010\b\u001a\u00020\u000fH\u0096 J\u0013\u0010\u0010\u001a\u00020\u00062\b\u0010\b\u001a\u0004\u0018\u00010\u0011H\u0096 J\u0012\u0010\u0012\u001a\u00020\u00062\b\u0010\u0013\u001a\u0004\u0018\u00010\u0014H\u0016J\u0012\u0010\u0015\u001a\u00020\u00062\b\u0010\u0016\u001a\u0004\u0018\u00010\u0017H\u0016J\t\u0010\u0018\u001a\u00020\u0006H\u0082 J\u0013\u0010\u0019\u001a\u00020\u00062\b\u0010\u0013\u001a\u0004\u0018\u00010\u0001H\u0082 J\u0013\u0010\u001a\u001a\u00020\u00062\b\u0010\u0016\u001a\u0004\u0018\u00010\u001bH\u0082 ¨\u0006\u001c"}, d2 = {"Lcom/facebook/react/bridge/WritableNativeArray;", "Lcom/facebook/react/bridge/ReadableNativeArray;", "Lcom/facebook/react/bridge/WritableArray;", "<init>", "()V", "pushNull", "", "pushBoolean", "value", "", "pushDouble", "", "pushInt", "", "pushLong", "", "pushString", "", "pushArray", "array", "Lcom/facebook/react/bridge/ReadableArray;", "pushMap", "map", "Lcom/facebook/react/bridge/ReadableMap;", "initHybrid", "pushNativeArray", "pushNativeMap", "Lcom/facebook/react/bridge/ReadableNativeMap;", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class WritableNativeArray extends ReadableNativeArray implements WritableArray {
    private final native void initHybrid();

    private final native void pushNativeArray(ReadableNativeArray array);

    private final native void pushNativeMap(ReadableNativeMap map);

    @Override // com.facebook.react.bridge.WritableArray
    public native void pushBoolean(boolean value);

    @Override // com.facebook.react.bridge.WritableArray
    public native void pushDouble(double value);

    @Override // com.facebook.react.bridge.WritableArray
    public native void pushInt(int value);

    @Override // com.facebook.react.bridge.WritableArray
    public native void pushLong(long value);

    @Override // com.facebook.react.bridge.WritableArray
    public native void pushNull();

    @Override // com.facebook.react.bridge.WritableArray
    public native void pushString(String value);

    public WritableNativeArray() {
        initHybrid();
    }

    @Override // com.facebook.react.bridge.WritableArray
    public void pushArray(ReadableArray array) {
        if (array != null && !(array instanceof ReadableNativeArray)) {
            throw new IllegalStateException("Illegal type provided".toString());
        }
        pushNativeArray((ReadableNativeArray) array);
    }

    @Override // com.facebook.react.bridge.WritableArray
    public void pushMap(ReadableMap map) {
        if (map != null && !(map instanceof ReadableNativeMap)) {
            throw new IllegalStateException("Illegal type provided".toString());
        }
        pushNativeMap((ReadableNativeMap) map);
    }
}
