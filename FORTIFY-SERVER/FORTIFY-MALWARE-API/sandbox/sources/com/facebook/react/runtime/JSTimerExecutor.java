package com.facebook.react.runtime;

import com.facebook.jni.HybridData;
import com.facebook.react.bridge.WritableArray;
import com.facebook.react.bridge.WritableNativeArray;
import com.facebook.react.modules.core.JavaScriptTimerExecutor;
import com.facebook.soloader.SoLoader;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: JSTimerExecutor.kt */
@Metadata(d1 = {"\u00004\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0006\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0002\b\u0001\u0018\u0000 \u00112\u00020\u0001:\u0001\u0011B\u000f\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0004\b\u0004\u0010\u0005J\u0011\u0010\u0006\u001a\u00020\u00072\u0006\u0010\b\u001a\u00020\tH\u0082 J\u0010\u0010\u0006\u001a\u00020\u00072\u0006\u0010\b\u001a\u00020\nH\u0016J\u0010\u0010\u000b\u001a\u00020\u00072\u0006\u0010\f\u001a\u00020\rH\u0016J\u0010\u0010\u000e\u001a\u00020\u00072\u0006\u0010\u000f\u001a\u00020\u0010H\u0016R\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\u0012"}, d2 = {"Lcom/facebook/react/runtime/JSTimerExecutor;", "Lcom/facebook/react/modules/core/JavaScriptTimerExecutor;", "mHybridData", "Lcom/facebook/jni/HybridData;", "<init>", "(Lcom/facebook/jni/HybridData;)V", "callTimers", "", "timerIDs", "Lcom/facebook/react/bridge/WritableNativeArray;", "Lcom/facebook/react/bridge/WritableArray;", "callIdleCallbacks", "frameTime", "", "emitTimeDriftWarning", "warningMessage", "", "Companion", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class JSTimerExecutor implements JavaScriptTimerExecutor {
    private static final Companion Companion = new Companion(null);
    private final HybridData mHybridData;

    private final native void callTimers(WritableNativeArray timerIDs);

    @Override // com.facebook.react.modules.core.JavaScriptTimerExecutor
    public void callIdleCallbacks(double frameTime) {
    }

    @Override // com.facebook.react.modules.core.JavaScriptTimerExecutor
    public void emitTimeDriftWarning(String warningMessage) {
        Intrinsics.checkNotNullParameter(warningMessage, "warningMessage");
    }

    public JSTimerExecutor(HybridData mHybridData) {
        Intrinsics.checkNotNullParameter(mHybridData, "mHybridData");
        this.mHybridData = mHybridData;
    }

    @Override // com.facebook.react.modules.core.JavaScriptTimerExecutor
    public void callTimers(WritableArray timerIDs) {
        Intrinsics.checkNotNullParameter(timerIDs, "timerIDs");
        callTimers((WritableNativeArray) timerIDs);
    }

    /* compiled from: JSTimerExecutor.kt */
    @Metadata(d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\b\u0082\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003¨\u0006\u0004"}, d2 = {"Lcom/facebook/react/runtime/JSTimerExecutor$Companion;", "", "<init>", "()V", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
    private static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }
    }

    static {
        SoLoader.loadLibrary("rninstance");
    }
}
