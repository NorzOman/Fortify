package com.facebook.react.bridge.interop;

import com.facebook.react.bridge.JavaScriptModule;
import com.facebook.react.internal.featureflags.ReactNativeFeatureFlags;
import java.util.LinkedHashMap;
import java.util.Map;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: InteropModuleRegistry.kt */
@Metadata(d1 = {"\u0000,\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0010%\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\u0002\n\u0002\b\u0004\b\u0000\u0018\u00002\u00020\u0001B\u0007¢\u0006\u0004\b\u0002\u0010\u0003J \u0010\u0007\u001a\u00020\b\"\n\b\u0000\u0010\t*\u0004\u0018\u00010\n2\f\u0010\u000b\u001a\b\u0012\u0004\u0012\u0002H\t0\u0006J'\u0010\f\u001a\u0004\u0018\u0001H\t\"\n\b\u0000\u0010\t*\u0004\u0018\u00010\n2\f\u0010\u000b\u001a\b\u0012\u0004\u0012\u0002H\t0\u0006¢\u0006\u0002\u0010\rJ(\u0010\u000e\u001a\u00020\u000f\"\n\b\u0000\u0010\t*\u0004\u0018\u00010\n2\f\u0010\u0010\u001a\b\u0012\u0004\u0012\u0002H\t0\u00062\u0006\u0010\u0011\u001a\u00020\u0001J\b\u0010\u0012\u001a\u00020\bH\u0002R \u0010\u0004\u001a\u0014\u0012\b\u0012\u0006\u0012\u0002\b\u00030\u0006\u0012\u0006\u0012\u0004\u0018\u00010\u00010\u0005X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\u0013"}, d2 = {"Lcom/facebook/react/bridge/interop/InteropModuleRegistry;", "", "<init>", "()V", "supportedModules", "", "Ljava/lang/Class;", "shouldReturnInteropModule", "", "T", "Lcom/facebook/react/bridge/JavaScriptModule;", "requestedModule", "getInteropModule", "(Ljava/lang/Class;)Lcom/facebook/react/bridge/JavaScriptModule;", "registerInteropModule", "", "interopModuleInterface", "interopModule", "checkReactFeatureFlagsConditions", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class InteropModuleRegistry {
    private final Map<Class<?>, Object> supportedModules = new LinkedHashMap();

    public final <T extends JavaScriptModule> boolean shouldReturnInteropModule(Class<T> requestedModule) {
        Intrinsics.checkNotNullParameter(requestedModule, "requestedModule");
        return checkReactFeatureFlagsConditions() && this.supportedModules.containsKey(requestedModule);
    }

    public final <T extends JavaScriptModule> T getInteropModule(Class<T> requestedModule) {
        Intrinsics.checkNotNullParameter(requestedModule, "requestedModule");
        if (!checkReactFeatureFlagsConditions()) {
            return null;
        }
        Object obj = this.supportedModules.get(requestedModule);
        if (obj instanceof JavaScriptModule) {
            return (T) obj;
        }
        return null;
    }

    public final <T extends JavaScriptModule> void registerInteropModule(Class<T> interopModuleInterface, Object interopModule) {
        Intrinsics.checkNotNullParameter(interopModuleInterface, "interopModuleInterface");
        Intrinsics.checkNotNullParameter(interopModule, "interopModule");
        if (checkReactFeatureFlagsConditions()) {
            this.supportedModules.put(interopModuleInterface, interopModule);
        }
    }

    private final boolean checkReactFeatureFlagsConditions() {
        return ReactNativeFeatureFlags.enableFabricRenderer() && ReactNativeFeatureFlags.useFabricInterop();
    }
}
