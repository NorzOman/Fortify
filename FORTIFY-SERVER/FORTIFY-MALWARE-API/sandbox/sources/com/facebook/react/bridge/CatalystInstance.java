package com.facebook.react.bridge;

import com.facebook.react.bridge.queue.ReactQueueConfiguration;
import com.facebook.react.common.annotations.VisibleForTesting;
import com.facebook.react.internal.turbomodule.core.interfaces.TurboModuleRegistry;
import com.facebook.react.turbomodule.core.interfaces.CallInvokerHolder;
import com.facebook.react.turbomodule.core.interfaces.NativeMethodCallInvokerHolder;
import java.util.Collection;
import kotlin.Deprecated;
import kotlin.Metadata;

/* compiled from: CatalystInstance.kt */
@Deprecated(message = "This class is deprecated, please to migrate to new architecture using [com.facebook.react.defaults.DefaultReactHost] instead.")
@Metadata(d1 = {"\u0000ª\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0004\n\u0002\u0010\b\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010\u001e\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\bg\u0018\u00002\u00020\u00012\u00020\u00022\u00020\u0003J\b\u0010\u0004\u001a\u00020\u0005H&J\b\u0010\u0006\u001a\u00020\u0007H&J\u0018\u0010\f\u001a\u00020\u00052\u0006\u0010\r\u001a\u00020\u000e2\u0006\u0010\u000f\u001a\u00020\u0010H'J\"\u0010\u0011\u001a\u00020\u00052\u0006\u0010\u0012\u001a\u00020\t2\u0006\u0010\u0013\u001a\u00020\t2\b\u0010\u000f\u001a\u0004\u0018\u00010\u0014H'J\b\u0010\u0015\u001a\u00020\u0005H&J\b\u0010\u0018\u001a\u00020\u0005H'J'\u0010\u001d\u001a\u0004\u0018\u0001H\u001e\"\b\b\u0000\u0010\u001e*\u00020\u001f2\f\u0010 \u001a\b\u0012\u0004\u0012\u0002H\u001e0!H&¢\u0006\u0002\u0010\"J \u0010#\u001a\u00020\u0007\"\b\b\u0000\u0010\u001e*\u00020$2\f\u0010%\u001a\b\u0012\u0004\u0012\u0002H\u001e0!H&J'\u0010&\u001a\u0004\u0018\u0001H\u001e\"\b\b\u0000\u0010\u001e*\u00020$2\f\u0010%\u001a\b\u0012\u0004\u0012\u0002H\u001e0!H&¢\u0006\u0002\u0010'J\u0012\u0010&\u001a\u0004\u0018\u00010$2\u0006\u0010(\u001a\u00020\tH&J\u0010\u0010-\u001a\u00020\u00052\u0006\u0010.\u001a\u00020/H&J\u0010\u00100\u001a\u00020\u00052\u0006\u00101\u001a\u000202H&J\u0010\u00103\u001a\u00020\u00052\u0006\u00101\u001a\u000202H&J\u0018\u00104\u001a\u00020\u00052\u0006\u00105\u001a\u00020\u000e2\u0006\u00106\u001a\u00020\tH&J\u0018\u00107\u001a\u00020\u00052\u0006\u00108\u001a\u00020\t2\u0006\u00109\u001a\u00020\tH'J\u0010\u0010P\u001a\u00020\u00052\u0006\u0010Q\u001a\u00020RH'J\u0010\u0010S\u001a\u00020\u00052\u0006\u0010T\u001a\u00020UH'J\n\u0010V\u001a\u0004\u0018\u00010UH'R\u0014\u0010\b\u001a\u0004\u0018\u00010\tX¦\u0004¢\u0006\u0006\u001a\u0004\b\n\u0010\u000bR\u0012\u0010\u0016\u001a\u00020\u0007X¦\u0004¢\u0006\u0006\u001a\u0004\b\u0016\u0010\u0017R\u0012\u0010\u0019\u001a\u00020\u001aX¦\u0004¢\u0006\u0006\u001a\u0004\b\u001b\u0010\u001cR\u0018\u0010)\u001a\b\u0012\u0004\u0012\u00020$0*X¦\u0004¢\u0006\u0006\u001a\u0004\b+\u0010,R\u0014\u0010:\u001a\u00020;8gX¦\u0004¢\u0006\u0006\u001a\u0004\b<\u0010=R\u0014\u0010>\u001a\u0004\u0018\u00010?X¦\u0004¢\u0006\u0006\u001a\u0004\b@\u0010AR\u0014\u0010B\u001a\u0004\u0018\u00010CX¦\u0004¢\u0006\u0006\u001a\u0004\bD\u0010ER\u001a\u0010F\u001a\u00020G8gX¦\u0004¢\u0006\f\u0012\u0004\bH\u0010I\u001a\u0004\bJ\u0010KR\u0012\u0010L\u001a\u00020MX¦\u0004¢\u0006\u0006\u001a\u0004\bN\u0010Oø\u0001\u0000\u0082\u0002\u0006\n\u0004\b!0\u0001¨\u0006WÀ\u0006\u0001"}, d2 = {"Lcom/facebook/react/bridge/CatalystInstance;", "Lcom/facebook/react/bridge/MemoryPressureListener;", "Lcom/facebook/react/bridge/JSInstance;", "Lcom/facebook/react/bridge/JSBundleLoaderDelegate;", "runJSBundle", "", "hasRunJSBundle", "", "sourceURL", "", "getSourceURL", "()Ljava/lang/String;", "invokeCallback", "callbackID", "", "arguments", "Lcom/facebook/react/bridge/NativeArrayInterface;", "callFunction", "module", "method", "Lcom/facebook/react/bridge/NativeArray;", "destroy", "isDestroyed", "()Z", "initialize", "reactQueueConfiguration", "Lcom/facebook/react/bridge/queue/ReactQueueConfiguration;", "getReactQueueConfiguration", "()Lcom/facebook/react/bridge/queue/ReactQueueConfiguration;", "getJSModule", "T", "Lcom/facebook/react/bridge/JavaScriptModule;", "jsInterface", "Ljava/lang/Class;", "(Ljava/lang/Class;)Lcom/facebook/react/bridge/JavaScriptModule;", "hasNativeModule", "Lcom/facebook/react/bridge/NativeModule;", "nativeModuleInterface", "getNativeModule", "(Ljava/lang/Class;)Lcom/facebook/react/bridge/NativeModule;", "moduleName", "nativeModules", "", "getNativeModules", "()Ljava/util/Collection;", "extendNativeModules", "modules", "Lcom/facebook/react/bridge/NativeModuleRegistry;", "addBridgeIdleDebugListener", "listener", "Lcom/facebook/react/bridge/NotThreadSafeBridgeIdleDebugListener;", "removeBridgeIdleDebugListener", "registerSegment", "segmentId", "path", "setGlobalVariable", "propName", "jsonValue", "javaScriptContextHolder", "Lcom/facebook/react/bridge/JavaScriptContextHolder;", "getJavaScriptContextHolder", "()Lcom/facebook/react/bridge/JavaScriptContextHolder;", "runtimeExecutor", "Lcom/facebook/react/bridge/RuntimeExecutor;", "getRuntimeExecutor", "()Lcom/facebook/react/bridge/RuntimeExecutor;", "runtimeScheduler", "Lcom/facebook/react/bridge/RuntimeScheduler;", "getRuntimeScheduler", "()Lcom/facebook/react/bridge/RuntimeScheduler;", "jsCallInvokerHolder", "Lcom/facebook/react/turbomodule/core/interfaces/CallInvokerHolder;", "getJSCallInvokerHolder$annotations", "()V", "getJSCallInvokerHolder", "()Lcom/facebook/react/turbomodule/core/interfaces/CallInvokerHolder;", "nativeMethodCallInvokerHolder", "Lcom/facebook/react/turbomodule/core/interfaces/NativeMethodCallInvokerHolder;", "getNativeMethodCallInvokerHolder", "()Lcom/facebook/react/turbomodule/core/interfaces/NativeMethodCallInvokerHolder;", "setTurboModuleRegistry", "turboModuleRegistry", "Lcom/facebook/react/internal/turbomodule/core/interfaces/TurboModuleRegistry;", "setFabricUIManager", "fabricUIManager", "Lcom/facebook/react/bridge/UIManager;", "getFabricUIManager", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public interface CatalystInstance extends MemoryPressureListener, JSInstance, JSBundleLoaderDelegate {
    static /* synthetic */ void getJSCallInvokerHolder$annotations() {
    }

    void addBridgeIdleDebugListener(NotThreadSafeBridgeIdleDebugListener listener);

    void callFunction(String module, String method, NativeArray arguments);

    void destroy();

    void extendNativeModules(NativeModuleRegistry modules);

    @Deprecated(message = "This method is deprecated, please to migrate to new architecture using [com.facebook.react.defaults.DefaultReactHost] instead.")
    UIManager getFabricUIManager();

    @Deprecated(message = "Use ReactContext.getJSCallInvokerHolder instead")
    CallInvokerHolder getJSCallInvokerHolder();

    <T extends JavaScriptModule> T getJSModule(Class<T> jsInterface);

    @Deprecated(message = "Use getRuntimeExecutor() instead.")
    JavaScriptContextHolder getJavaScriptContextHolder();

    NativeMethodCallInvokerHolder getNativeMethodCallInvokerHolder();

    <T extends NativeModule> T getNativeModule(Class<T> nativeModuleInterface);

    NativeModule getNativeModule(String moduleName);

    Collection<NativeModule> getNativeModules();

    ReactQueueConfiguration getReactQueueConfiguration();

    RuntimeExecutor getRuntimeExecutor();

    RuntimeScheduler getRuntimeScheduler();

    String getSourceURL();

    <T extends NativeModule> boolean hasNativeModule(Class<T> nativeModuleInterface);

    boolean hasRunJSBundle();

    @VisibleForTesting
    void initialize();

    @Override // com.facebook.react.bridge.JSInstance
    void invokeCallback(int callbackID, NativeArrayInterface arguments);

    boolean isDestroyed();

    void registerSegment(int segmentId, String path);

    void removeBridgeIdleDebugListener(NotThreadSafeBridgeIdleDebugListener listener);

    void runJSBundle();

    @Deprecated(message = "This method is deprecated, please to migrate to new architecture using [com.facebook.react.defaults.DefaultReactHost] instead.")
    void setFabricUIManager(UIManager fabricUIManager);

    @VisibleForTesting
    void setGlobalVariable(String propName, String jsonValue);

    @Deprecated(message = "This method is deprecated, please to migrate to new architecture using [com.facebook.react.defaults.DefaultReactHost] instead.")
    void setTurboModuleRegistry(TurboModuleRegistry turboModuleRegistry);
}
