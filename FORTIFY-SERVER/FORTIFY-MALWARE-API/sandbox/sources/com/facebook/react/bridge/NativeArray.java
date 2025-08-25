package com.facebook.react.bridge;

import com.facebook.jni.HybridClassBase;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* compiled from: NativeArray.kt */
@Metadata(d1 = {"\u0000\u0018\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0002\b\u0002\b'\u0018\u0000 \u00072\u00020\u00012\u00020\u0002:\u0001\u0007B\t\b\u0004¢\u0006\u0004\b\u0003\u0010\u0004J\t\u0010\u0005\u001a\u00020\u0006H\u0096 ¨\u0006\b"}, d2 = {"Lcom/facebook/react/bridge/NativeArray;", "Lcom/facebook/jni/HybridClassBase;", "Lcom/facebook/react/bridge/NativeArrayInterface;", "<init>", "()V", "toString", "", "Companion", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public abstract class NativeArray extends HybridClassBase implements NativeArrayInterface {
    private static final Companion Companion = new Companion(null);

    @Override // com.facebook.react.bridge.NativeArrayInterface
    public native String toString();

    protected NativeArray() {
    }

    /* compiled from: NativeArray.kt */
    @Metadata(d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\b\u0082\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003¨\u0006\u0004"}, d2 = {"Lcom/facebook/react/bridge/NativeArray$Companion;", "", "<init>", "()V", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
    private static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }
    }

    static {
        ReactBridge.staticInit();
    }
}
