package com.facebook.react.uimanager;

import android.app.Activity;
import android.content.Context;
import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.CatalystInstance;
import com.facebook.react.bridge.JavaScriptContextHolder;
import com.facebook.react.bridge.JavaScriptModule;
import com.facebook.react.bridge.LifecycleEventListener;
import com.facebook.react.bridge.NativeModule;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.bridge.UIManager;
import com.facebook.react.turbomodule.core.interfaces.CallInvokerHolder;
import java.util.Collection;

/* loaded from: classes.dex */
public class ThemedReactContext extends ReactContext {
    private final String mModuleName;
    private final ReactApplicationContext mReactApplicationContext;
    private final int mSurfaceId;

    @Deprecated
    public ThemedReactContext(ReactApplicationContext reactApplicationContext, Context context) {
        this(reactApplicationContext, context, null, -1);
    }

    @Deprecated
    public ThemedReactContext(ReactApplicationContext reactApplicationContext, Context context, String str) {
        this(reactApplicationContext, context, str, -1);
    }

    public ThemedReactContext(ReactApplicationContext reactApplicationContext, Context context, String str, int i) {
        super(context);
        initializeFromOther(reactApplicationContext);
        this.mReactApplicationContext = reactApplicationContext;
        this.mModuleName = str;
        this.mSurfaceId = i;
    }

    @Override // com.facebook.react.bridge.ReactContext
    public void addLifecycleEventListener(LifecycleEventListener lifecycleEventListener) {
        this.mReactApplicationContext.addLifecycleEventListener(lifecycleEventListener);
    }

    @Override // com.facebook.react.bridge.ReactContext
    public void removeLifecycleEventListener(LifecycleEventListener lifecycleEventListener) {
        this.mReactApplicationContext.removeLifecycleEventListener(lifecycleEventListener);
    }

    @Override // com.facebook.react.bridge.ReactContext
    public boolean hasCurrentActivity() {
        return this.mReactApplicationContext.hasCurrentActivity();
    }

    @Override // com.facebook.react.bridge.ReactContext
    public Activity getCurrentActivity() {
        return this.mReactApplicationContext.getCurrentActivity();
    }

    @Override // com.facebook.react.bridge.ReactContext
    public <T extends JavaScriptModule> T getJSModule(Class<T> cls) {
        return (T) this.mReactApplicationContext.getJSModule(cls);
    }

    @Override // com.facebook.react.bridge.ReactContext
    public <T extends NativeModule> boolean hasNativeModule(Class<T> cls) {
        return this.mReactApplicationContext.hasNativeModule(cls);
    }

    @Override // com.facebook.react.bridge.ReactContext
    public Collection<NativeModule> getNativeModules() {
        return this.mReactApplicationContext.getNativeModules();
    }

    @Override // com.facebook.react.bridge.ReactContext
    public <T extends NativeModule> T getNativeModule(Class<T> cls) {
        return (T) this.mReactApplicationContext.getNativeModule(cls);
    }

    @Override // com.facebook.react.bridge.ReactContext
    public NativeModule getNativeModule(String str) {
        return this.mReactApplicationContext.getNativeModule(str);
    }

    @Override // com.facebook.react.bridge.ReactContext
    public CatalystInstance getCatalystInstance() {
        return this.mReactApplicationContext.getCatalystInstance();
    }

    @Override // com.facebook.react.bridge.ReactContext
    @Deprecated
    public boolean hasActiveCatalystInstance() {
        return this.mReactApplicationContext.hasActiveCatalystInstance();
    }

    @Override // com.facebook.react.bridge.ReactContext
    public boolean hasActiveReactInstance() {
        return this.mReactApplicationContext.hasActiveCatalystInstance();
    }

    @Override // com.facebook.react.bridge.ReactContext
    public boolean hasCatalystInstance() {
        return this.mReactApplicationContext.hasCatalystInstance();
    }

    @Override // com.facebook.react.bridge.ReactContext
    public boolean hasReactInstance() {
        return this.mReactApplicationContext.hasReactInstance();
    }

    @Override // com.facebook.react.bridge.ReactContext
    public void destroy() {
        this.mReactApplicationContext.destroy();
    }

    @Deprecated
    public String getSurfaceID() {
        return this.mModuleName;
    }

    public String getModuleName() {
        return this.mModuleName;
    }

    public int getSurfaceId() {
        return this.mSurfaceId;
    }

    public ReactApplicationContext getReactApplicationContext() {
        return this.mReactApplicationContext;
    }

    @Override // com.facebook.react.bridge.ReactContext
    public void handleException(Exception exc) {
        this.mReactApplicationContext.handleException(exc);
    }

    @Override // com.facebook.react.bridge.ReactContext
    @Deprecated
    public boolean isBridgeless() {
        return this.mReactApplicationContext.isBridgeless();
    }

    @Override // com.facebook.react.bridge.ReactContext
    public JavaScriptContextHolder getJavaScriptContextHolder() {
        return this.mReactApplicationContext.getJavaScriptContextHolder();
    }

    @Override // com.facebook.react.bridge.ReactContext
    public CallInvokerHolder getJSCallInvokerHolder() {
        return this.mReactApplicationContext.getJSCallInvokerHolder();
    }

    @Override // com.facebook.react.bridge.ReactContext
    public UIManager getFabricUIManager() {
        return this.mReactApplicationContext.getFabricUIManager();
    }

    @Override // com.facebook.react.bridge.ReactContext
    public String getSourceURL() {
        return this.mReactApplicationContext.getSourceURL();
    }

    @Override // com.facebook.react.bridge.ReactContext
    public void registerSegment(int i, String str, Callback callback) {
        this.mReactApplicationContext.registerSegment(i, str, callback);
    }
}
