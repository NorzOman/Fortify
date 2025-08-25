package com.facebook.react.devsupport;

import android.app.Activity;
import android.view.View;
import com.facebook.react.bridge.JSBundleLoader;
import com.facebook.react.bridge.JavaJSExecutor;
import com.facebook.react.bridge.JavaScriptExecutorFactory;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.interfaces.TaskInterface;

/* loaded from: classes.dex */
public interface ReactInstanceDevHelper {
    View createRootView(String str);

    void destroyRootView(View view);

    Activity getCurrentActivity();

    ReactContext getCurrentReactContext();

    JavaScriptExecutorFactory getJavaScriptExecutorFactory();

    TaskInterface<Boolean> loadBundle(JSBundleLoader jSBundleLoader);

    void onJSBundleLoadedFromServer();

    void onReloadWithJSDebugger(JavaJSExecutor.Factory factory);

    void reload(String str);

    void toggleElementInspector();
}
