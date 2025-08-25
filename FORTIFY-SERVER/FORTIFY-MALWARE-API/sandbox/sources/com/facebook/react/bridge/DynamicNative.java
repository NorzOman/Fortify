package com.facebook.react.bridge;

import com.facebook.jni.HybridClassBase;
import kotlin.Metadata;

/* compiled from: DynamicNative.kt */
@Metadata(d1 = {"\u0000D\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0002\b\u0005\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u0006\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0000\b\u0003\u0018\u00002\u00020\u00012\u00020\u0002B\u0007¢\u0006\u0004\b\u0003\u0010\u0004J\t\u0010\f\u001a\u00020\u0006H\u0082 J\t\u0010\r\u001a\u00020\nH\u0082 J\t\u0010\u000e\u001a\u00020\nH\u0096 J\b\u0010\u000f\u001a\u00020\u0010H\u0016J\t\u0010\u0011\u001a\u00020\u0012H\u0096 J\t\u0010\u0013\u001a\u00020\u0014H\u0096 J\t\u0010\u0015\u001a\u00020\u0016H\u0096 J\t\u0010\u0017\u001a\u00020\u0018H\u0096 J\b\u0010\u0019\u001a\u00020\u001aH\u0016R\u0014\u0010\u0005\u001a\u00020\u00068VX\u0096\u0004¢\u0006\u0006\u001a\u0004\b\u0007\u0010\bR\u0014\u0010\t\u001a\u00020\n8VX\u0096\u0004¢\u0006\u0006\u001a\u0004\b\t\u0010\u000b¨\u0006\u001b"}, d2 = {"Lcom/facebook/react/bridge/DynamicNative;", "Lcom/facebook/jni/HybridClassBase;", "Lcom/facebook/react/bridge/Dynamic;", "<init>", "()V", "type", "Lcom/facebook/react/bridge/ReadableType;", "getType", "()Lcom/facebook/react/bridge/ReadableType;", "isNull", "", "()Z", "getTypeNative", "isNullNative", "asBoolean", "asInt", "", "asDouble", "", "asString", "", "asArray", "Lcom/facebook/react/bridge/ReadableArray;", "asMap", "Lcom/facebook/react/bridge/ReadableMap;", "recycle", "", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
final class DynamicNative extends HybridClassBase implements Dynamic {
    private final native ReadableType getTypeNative();

    private final native boolean isNullNative();

    @Override // com.facebook.react.bridge.Dynamic
    public native ReadableArray asArray();

    @Override // com.facebook.react.bridge.Dynamic
    public native boolean asBoolean();

    @Override // com.facebook.react.bridge.Dynamic
    public native double asDouble();

    @Override // com.facebook.react.bridge.Dynamic
    public native ReadableMap asMap();

    @Override // com.facebook.react.bridge.Dynamic
    public native String asString();

    @Override // com.facebook.react.bridge.Dynamic
    public void recycle() {
    }

    @Override // com.facebook.react.bridge.Dynamic
    public ReadableType getType() {
        return getTypeNative();
    }

    @Override // com.facebook.react.bridge.Dynamic
    public boolean isNull() {
        return isNullNative();
    }

    @Override // com.facebook.react.bridge.Dynamic
    public int asInt() {
        return (int) asDouble();
    }
}
