package com.facebook.hermes.reactexecutor;

import com.facebook.jni.HybridData;
import com.facebook.react.bridge.JavaScriptExecutor;
import com.facebook.react.common.build.ReactBuildConfig;
import com.facebook.soloader.SoLoader;
import javax.annotation.Nullable;

/* loaded from: classes.dex */
public class HermesExecutor extends JavaScriptExecutor {
    private static String mode_;

    private static native HybridData initHybrid(boolean z, String str, long j);

    private static native HybridData initHybridDefaultConfig(boolean z, String str);

    static {
        loadLibrary();
    }

    public static void loadLibrary() throws UnsatisfiedLinkError {
        if (mode_ == null) {
            SoLoader.loadLibrary("hermes");
            SoLoader.loadLibrary("hermes_executor");
            mode_ = ReactBuildConfig.DEBUG ? "Debug" : "Release";
        }
    }

    /* JADX WARN: Illegal instructions before constructor call */
    HermesExecutor(@Nullable RuntimeConfig runtimeConfig, boolean z, String str) {
        HybridData hybridDataInitHybrid;
        if (runtimeConfig == null) {
            hybridDataInitHybrid = initHybridDefaultConfig(z, str);
        } else {
            hybridDataInitHybrid = initHybrid(z, str, runtimeConfig.getHeapSizeMB());
        }
        super(hybridDataInitHybrid);
    }

    @Override // com.facebook.react.bridge.JavaScriptExecutor
    public String getName() {
        return "HermesExecutor" + mode_;
    }
}
