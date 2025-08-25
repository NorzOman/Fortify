package com.facebook.react.fabric.events;

import com.facebook.jni.HybridClassBase;
import com.facebook.react.bridge.NativeMap;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.fabric.FabricSoLoader;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: EventEmitterWrapper.kt */
@Metadata(d1 = {"\u0000.\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0005\b\u0007\u0018\u0000 \u00132\u00020\u0001:\u0001\u0013B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003J#\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u00072\b\u0010\b\u001a\u0004\u0018\u00010\t2\u0006\u0010\n\u001a\u00020\u000bH\u0082 J\u001b\u0010\f\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u00072\b\u0010\b\u001a\u0004\u0018\u00010\tH\u0082 J\u001b\u0010\r\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u00072\b\u0010\b\u001a\u0004\u0018\u00010\tH\u0082 J \u0010\u000e\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u00072\b\u0010\b\u001a\u0004\u0018\u00010\u000f2\u0006\u0010\u0010\u001a\u00020\u000bJ\u0018\u0010\f\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u00072\b\u0010\b\u001a\u0004\u0018\u00010\u000fJ\u0018\u0010\u0011\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u00072\b\u0010\b\u001a\u0004\u0018\u00010\u000fJ\u0006\u0010\u0012\u001a\u00020\u0005¨\u0006\u0014"}, d2 = {"Lcom/facebook/react/fabric/events/EventEmitterWrapper;", "Lcom/facebook/jni/HybridClassBase;", "<init>", "()V", "dispatchEvent", "", "eventName", "", "params", "Lcom/facebook/react/bridge/NativeMap;", "category", "", "dispatchEventSynchronously", "dispatchUniqueEvent", "dispatch", "Lcom/facebook/react/bridge/WritableMap;", "eventCategory", "dispatchUnique", "destroy", "Companion", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class EventEmitterWrapper extends HybridClassBase {
    private static final Companion Companion = new Companion(null);

    private final native void dispatchEvent(String eventName, NativeMap params, int category);

    private final native void dispatchEventSynchronously(String eventName, NativeMap params);

    private final native void dispatchUniqueEvent(String eventName, NativeMap params);

    private EventEmitterWrapper() {
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final synchronized void dispatch(String eventName, WritableMap params, int eventCategory) {
        Intrinsics.checkNotNullParameter(eventName, "eventName");
        if (isValid()) {
            dispatchEvent(eventName, (NativeMap) params, eventCategory);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final synchronized void dispatchEventSynchronously(String eventName, WritableMap params) {
        Intrinsics.checkNotNullParameter(eventName, "eventName");
        if (isValid()) {
            dispatchEventSynchronously(eventName, (NativeMap) params);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final synchronized void dispatchUnique(String eventName, WritableMap params) {
        Intrinsics.checkNotNullParameter(eventName, "eventName");
        if (isValid()) {
            dispatchUniqueEvent(eventName, (NativeMap) params);
        }
    }

    public final synchronized void destroy() {
        if (isValid()) {
            resetNative();
        }
    }

    /* compiled from: EventEmitterWrapper.kt */
    @Metadata(d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\b\u0082\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003¨\u0006\u0004"}, d2 = {"Lcom/facebook/react/fabric/events/EventEmitterWrapper$Companion;", "", "<init>", "()V", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
    private static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }
    }

    static {
        FabricSoLoader.staticInit();
    }
}
