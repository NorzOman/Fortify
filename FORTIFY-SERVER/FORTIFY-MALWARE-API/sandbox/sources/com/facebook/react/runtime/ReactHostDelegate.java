package com.facebook.react.runtime;

import com.facebook.react.ReactPackage;
import com.facebook.react.ReactPackageTurboModuleManagerDelegate;
import com.facebook.react.bridge.JSBundleLoader;
import com.facebook.react.common.annotations.UnstableReactNativeAPI;
import java.util.List;
import kotlin.Metadata;

/* compiled from: ReactHostDelegate.kt */
@Metadata(d1 = {"\u0000N\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\bg\u0018\u00002\u00020\u0001J\u0014\u0010\u001b\u001a\u00020\u001c2\n\u0010\u001d\u001a\u00060\u001ej\u0002`\u001fH&R\u0012\u0010\u0002\u001a\u00020\u0003X¦\u0004¢\u0006\u0006\u001a\u0004\b\u0004\u0010\u0005R\u0014\u0010\u0006\u001a\u0004\u0018\u00010\u0007X¦\u0004¢\u0006\u0006\u001a\u0004\b\b\u0010\tR\u0018\u0010\n\u001a\b\u0012\u0004\u0012\u00020\f0\u000bX¦\u0004¢\u0006\u0006\u001a\u0004\b\r\u0010\u000eR\u0012\u0010\u000f\u001a\u00020\u0010X¦\u0004¢\u0006\u0006\u001a\u0004\b\u0011\u0010\u0012R\u0012\u0010\u0013\u001a\u00020\u0014X¦\u0004¢\u0006\u0006\u001a\u0004\b\u0015\u0010\u0016R\u0012\u0010\u0017\u001a\u00020\u0018X¦\u0004¢\u0006\u0006\u001a\u0004\b\u0019\u0010\u001aø\u0001\u0000\u0082\u0002\u0006\n\u0004\b!0\u0001¨\u0006 À\u0006\u0001"}, d2 = {"Lcom/facebook/react/runtime/ReactHostDelegate;", "", "jsMainModulePath", "", "getJsMainModulePath", "()Ljava/lang/String;", "bindingsInstaller", "Lcom/facebook/react/runtime/BindingsInstaller;", "getBindingsInstaller", "()Lcom/facebook/react/runtime/BindingsInstaller;", "reactPackages", "", "Lcom/facebook/react/ReactPackage;", "getReactPackages", "()Ljava/util/List;", "jsRuntimeFactory", "Lcom/facebook/react/runtime/JSRuntimeFactory;", "getJsRuntimeFactory", "()Lcom/facebook/react/runtime/JSRuntimeFactory;", "jsBundleLoader", "Lcom/facebook/react/bridge/JSBundleLoader;", "getJsBundleLoader", "()Lcom/facebook/react/bridge/JSBundleLoader;", "turboModuleManagerDelegateBuilder", "Lcom/facebook/react/ReactPackageTurboModuleManagerDelegate$Builder;", "getTurboModuleManagerDelegateBuilder", "()Lcom/facebook/react/ReactPackageTurboModuleManagerDelegate$Builder;", "handleInstanceException", "", "error", "Ljava/lang/Exception;", "Lkotlin/Exception;", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
@UnstableReactNativeAPI
/* loaded from: classes.dex */
public interface ReactHostDelegate {
    BindingsInstaller getBindingsInstaller();

    JSBundleLoader getJsBundleLoader();

    String getJsMainModulePath();

    JSRuntimeFactory getJsRuntimeFactory();

    List<ReactPackage> getReactPackages();

    ReactPackageTurboModuleManagerDelegate.Builder getTurboModuleManagerDelegateBuilder();

    void handleInstanceException(Exception error);
}
