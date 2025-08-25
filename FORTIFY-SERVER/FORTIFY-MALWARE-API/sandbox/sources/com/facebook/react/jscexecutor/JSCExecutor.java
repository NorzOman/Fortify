package com.facebook.react.jscexecutor;

import com.facebook.jni.HybridData;
import com.facebook.react.bridge.JavaScriptExecutor;
import com.facebook.react.bridge.ReadableNativeMap;
import com.facebook.soloader.SoLoader;
import kotlin.Metadata;
import kotlin.jvm.JvmStatic;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: JSCExecutor.kt */
@Metadata(d1 = {"\u0000\u001a\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0002\b\u0002\b\u0007\u0018\u0000 \b2\u00020\u0001:\u0001\bB\u0011\b\u0000\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0004\b\u0004\u0010\u0005J\b\u0010\u0006\u001a\u00020\u0007H\u0016¨\u0006\t"}, d2 = {"Lcom/facebook/react/jscexecutor/JSCExecutor;", "Lcom/facebook/react/bridge/JavaScriptExecutor;", "jscConfig", "Lcom/facebook/react/bridge/ReadableNativeMap;", "<init>", "(Lcom/facebook/react/bridge/ReadableNativeMap;)V", "getName", "", "Companion", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class JSCExecutor extends JavaScriptExecutor {
    private static final Companion Companion;

    /* JADX INFO: Access modifiers changed from: private */
    @JvmStatic
    public static final native HybridData initHybrid(ReadableNativeMap readableNativeMap);

    @JvmStatic
    public static final void loadLibrary() throws UnsatisfiedLinkError {
        Companion.loadLibrary();
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public JSCExecutor(ReadableNativeMap jscConfig) {
        super(Companion.initHybrid(jscConfig));
        Intrinsics.checkNotNullParameter(jscConfig, "jscConfig");
    }

    @Override // com.facebook.react.bridge.JavaScriptExecutor
    public String getName() {
        return "JSCExecutor";
    }

    /* compiled from: JSCExecutor.kt */
    @Metadata(d1 = {"\u0000\u001e\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\b\u0082\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003J\b\u0010\u0004\u001a\u00020\u0005H\u0007J\u0011\u0010\u0006\u001a\u00020\u00072\u0006\u0010\b\u001a\u00020\tH\u0083 ¨\u0006\n"}, d2 = {"Lcom/facebook/react/jscexecutor/JSCExecutor$Companion;", "", "<init>", "()V", "loadLibrary", "", "initHybrid", "Lcom/facebook/jni/HybridData;", "jscConfig", "Lcom/facebook/react/bridge/ReadableNativeMap;", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
    private static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        /* JADX INFO: Access modifiers changed from: private */
        @JvmStatic
        public final HybridData initHybrid(ReadableNativeMap jscConfig) {
            return JSCExecutor.initHybrid(jscConfig);
        }

        private Companion() {
        }

        @JvmStatic
        public final void loadLibrary() throws UnsatisfiedLinkError {
            SoLoader.loadLibrary("jscexecutor");
        }
    }

    static {
        Companion companion = new Companion(null);
        Companion = companion;
        companion.loadLibrary();
    }
}
