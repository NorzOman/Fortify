package com.facebook.react.runtime.hermes;

import com.facebook.jni.HybridData;
import com.facebook.react.runtime.JSRuntimeFactory;
import com.facebook.soloader.SoLoader;
import kotlin.Metadata;
import kotlin.jvm.JvmStatic;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* compiled from: HermesInstance.kt */
@Metadata(d1 = {"\u0000\u0012\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0005\u0018\u0000 \u00072\u00020\u0001:\u0001\u0007B\u000f\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0004\b\u0004\u0010\u0005B\t\b\u0016¢\u0006\u0004\b\u0004\u0010\u0006¨\u0006\b"}, d2 = {"Lcom/facebook/react/runtime/hermes/HermesInstance;", "Lcom/facebook/react/runtime/JSRuntimeFactory;", "allocInOldGenBeforeTTI", "", "<init>", "(Z)V", "()V", "Companion", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class HermesInstance extends JSRuntimeFactory {

    /* renamed from: Companion, reason: from kotlin metadata */
    public static final Companion INSTANCE = new Companion(null);

    @JvmStatic
    protected static final native HybridData initHybrid(boolean z);

    public HermesInstance(boolean z) {
        super(initHybrid(z));
    }

    public HermesInstance() {
        this(false);
    }

    /* compiled from: HermesInstance.kt */
    @Metadata(d1 = {"\u0000\u0018\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0000\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003J\u0011\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u0007H\u0085 ¨\u0006\b"}, d2 = {"Lcom/facebook/react/runtime/hermes/HermesInstance$Companion;", "", "<init>", "()V", "initHybrid", "Lcom/facebook/jni/HybridData;", "allocInOldGenBeforeTTI", "", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @JvmStatic
        protected final HybridData initHybrid(boolean allocInOldGenBeforeTTI) {
            return HermesInstance.initHybrid(allocInOldGenBeforeTTI);
        }

        private Companion() {
        }
    }

    static {
        SoLoader.loadLibrary("hermesinstancejni");
    }
}
