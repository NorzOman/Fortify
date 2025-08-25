package com.facebook.react;

import android.app.Application;
import com.facebook.infer.annotation.Assertions;
import com.facebook.react.ReactPackageTurboModuleManagerDelegate;
import com.facebook.react.bridge.JSExceptionHandler;
import com.facebook.react.bridge.JavaScriptExecutorFactory;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactMarker;
import com.facebook.react.bridge.ReactMarkerConstants;
import com.facebook.react.bridge.UIManager;
import com.facebook.react.bridge.UIManagerProvider;
import com.facebook.react.common.LifecycleState;
import com.facebook.react.common.SurfaceDelegate;
import com.facebook.react.common.SurfaceDelegateFactory;
import com.facebook.react.devsupport.DevSupportManagerFactory;
import com.facebook.react.devsupport.interfaces.DevLoadingViewManager;
import com.facebook.react.devsupport.interfaces.PausedInDebuggerOverlayManager;
import com.facebook.react.devsupport.interfaces.RedBoxHandler;
import com.facebook.react.internal.ChoreographerProvider;
import java.util.Iterator;
import java.util.List;

/* loaded from: classes.dex */
public abstract class ReactNativeHost {
    private final Application mApplication;
    private ReactInstanceManager mReactInstanceManager;

    static /* synthetic */ UIManager lambda$getUIManagerProvider$0(ReactApplicationContext reactApplicationContext) {
        return null;
    }

    protected ChoreographerProvider getChoreographerProvider() {
        return null;
    }

    protected DevLoadingViewManager getDevLoadingViewManager() {
        return null;
    }

    protected DevSupportManagerFactory getDevSupportManagerFactory() {
        return null;
    }

    protected String getJSBundleFile() {
        return null;
    }

    protected JSEngineResolutionAlgorithm getJSEngineResolutionAlgorithm() {
        return null;
    }

    protected JSExceptionHandler getJSExceptionHandler() {
        return null;
    }

    protected JavaScriptExecutorFactory getJavaScriptExecutorFactory() {
        return null;
    }

    public boolean getLazyViewManagersEnabled() {
        return false;
    }

    protected abstract List<ReactPackage> getPackages();

    protected PausedInDebuggerOverlayManager getPausedInDebuggerOverlayManager() {
        return null;
    }

    protected ReactPackageTurboModuleManagerDelegate.Builder getReactPackageTurboModuleManagerDelegateBuilder() {
        return null;
    }

    protected RedBoxHandler getRedBoxHandler() {
        return null;
    }

    public boolean getShouldRequireActivity() {
        return true;
    }

    public abstract boolean getUseDeveloperSupport();

    protected ReactNativeHost(Application application) {
        this.mApplication = application;
    }

    public synchronized ReactInstanceManager getReactInstanceManager() {
        if (this.mReactInstanceManager == null) {
            ReactMarker.logMarker(ReactMarkerConstants.INIT_REACT_RUNTIME_START);
            ReactMarker.logMarker(ReactMarkerConstants.GET_REACT_INSTANCE_MANAGER_START);
            this.mReactInstanceManager = createReactInstanceManager();
            ReactMarker.logMarker(ReactMarkerConstants.GET_REACT_INSTANCE_MANAGER_END);
        }
        return this.mReactInstanceManager;
    }

    public synchronized boolean hasInstance() {
        return this.mReactInstanceManager != null;
    }

    public synchronized void clear() {
        ReactInstanceManager reactInstanceManager = this.mReactInstanceManager;
        if (reactInstanceManager != null) {
            reactInstanceManager.invalidate();
            this.mReactInstanceManager = null;
        }
    }

    protected ReactInstanceManager createReactInstanceManager() {
        ReactMarker.logMarker(ReactMarkerConstants.BUILD_REACT_INSTANCE_MANAGER_START);
        ReactInstanceManagerBuilder baseReactInstanceManagerBuilder = getBaseReactInstanceManagerBuilder();
        ReactMarker.logMarker(ReactMarkerConstants.BUILD_REACT_INSTANCE_MANAGER_END);
        return baseReactInstanceManagerBuilder.build();
    }

    protected ReactInstanceManagerBuilder getBaseReactInstanceManagerBuilder() {
        ReactInstanceManagerBuilder pausedInDebuggerOverlayManager = ReactInstanceManager.builder().setApplication(this.mApplication).setJSMainModulePath(getJSMainModuleName()).setUseDeveloperSupport(getUseDeveloperSupport()).setDevSupportManagerFactory(getDevSupportManagerFactory()).setDevLoadingViewManager(getDevLoadingViewManager()).setRequireActivity(getShouldRequireActivity()).setSurfaceDelegateFactory(getSurfaceDelegateFactory()).setJSExceptionHandler(getJSExceptionHandler()).setLazyViewManagersEnabled(getLazyViewManagersEnabled()).setRedBoxHandler(getRedBoxHandler()).setJavaScriptExecutorFactory(getJavaScriptExecutorFactory()).setUIManagerProvider(getUIManagerProvider()).setInitialLifecycleState(LifecycleState.BEFORE_CREATE).setReactPackageTurboModuleManagerDelegateBuilder(getReactPackageTurboModuleManagerDelegateBuilder()).setJSEngineResolutionAlgorithm(getJSEngineResolutionAlgorithm()).setChoreographerProvider(getChoreographerProvider()).setPausedInDebuggerOverlayManager(getPausedInDebuggerOverlayManager());
        Iterator<ReactPackage> it = getPackages().iterator();
        while (it.hasNext()) {
            pausedInDebuggerOverlayManager.addPackage(it.next());
        }
        String jSBundleFile = getJSBundleFile();
        if (jSBundleFile != null) {
            pausedInDebuggerOverlayManager.setJSBundleFile(jSBundleFile);
        } else {
            pausedInDebuggerOverlayManager.setBundleAssetName((String) Assertions.assertNotNull(getBundleAssetName()));
        }
        return pausedInDebuggerOverlayManager;
    }

    protected final Application getApplication() {
        return this.mApplication;
    }

    protected UIManagerProvider getUIManagerProvider() {
        return new UIManagerProvider() { // from class: com.facebook.react.ReactNativeHost$$ExternalSyntheticLambda0
            @Override // com.facebook.react.bridge.UIManagerProvider
            public final UIManager createUIManager(ReactApplicationContext reactApplicationContext) {
                return ReactNativeHost.lambda$getUIManagerProvider$0(reactApplicationContext);
            }
        };
    }

    public SurfaceDelegateFactory getSurfaceDelegateFactory() {
        return new SurfaceDelegateFactory() { // from class: com.facebook.react.ReactNativeHost.1
            @Override // com.facebook.react.common.SurfaceDelegateFactory
            public SurfaceDelegate createSurfaceDelegate(String str) {
                return null;
            }
        };
    }

    protected String getJSMainModuleName() {
        return "index.android";
    }

    protected String getBundleAssetName() {
        return "index.android.bundle";
    }
}
