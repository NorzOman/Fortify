package com.facebook.react.bridge;

import com.facebook.jni.HybridData;
import com.facebook.react.devsupport.inspector.InspectorNetworkRequestListener;
import java.util.Map;
import java.util.concurrent.Executor;
import javax.annotation.Nullable;

/* loaded from: classes.dex */
public class ReactInstanceManagerInspectorTarget implements AutoCloseable {
    private final HybridData mHybridData;

    public interface TargetDelegate {
        Map<String, String> getMetadata();

        void loadNetworkResource(String str, InspectorNetworkRequestListener inspectorNetworkRequestListener);

        void onReload();

        void onSetPausedInDebuggerMessage(@Nullable String str);
    }

    private native HybridData initHybrid(Executor executor, TargetDelegate targetDelegate);

    public native void sendDebuggerResumeCommand();

    public ReactInstanceManagerInspectorTarget(TargetDelegate targetDelegate) {
        this.mHybridData = initHybrid(new Executor() { // from class: com.facebook.react.bridge.ReactInstanceManagerInspectorTarget.1
            @Override // java.util.concurrent.Executor
            public void execute(Runnable runnable) {
                if (UiThreadUtil.isOnUiThread()) {
                    runnable.run();
                } else {
                    UiThreadUtil.runOnUiThread(runnable);
                }
            }
        }, targetDelegate);
    }

    @Override // java.lang.AutoCloseable
    public void close() {
        this.mHybridData.resetNative();
    }

    boolean isValid() {
        return this.mHybridData.isValid();
    }

    static {
        ReactBridge.staticInit();
    }
}
