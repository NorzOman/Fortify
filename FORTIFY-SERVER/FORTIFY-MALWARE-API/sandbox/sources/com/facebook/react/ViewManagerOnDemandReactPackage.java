package com.facebook.react;

import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.uimanager.ViewManager;
import java.util.Collection;
import kotlin.Metadata;

/* compiled from: ViewManagerOnDemandReactPackage.kt */
@Metadata(d1 = {"\u0000&\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u001e\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0001\n\u0002\b\u0002\bf\u0018\u00002\u00020\u0001J\u0016\u0010\u0002\u001a\b\u0012\u0004\u0012\u00020\u00040\u00032\u0006\u0010\u0005\u001a\u00020\u0006H&J*\u0010\u0007\u001a\u0014\u0012\u0006\b\u0000\u0012\u00020\t\u0012\u0006\b\u0000\u0012\u00020\t\u0018\u00010\b2\u0006\u0010\u0005\u001a\u00020\u00062\u0006\u0010\n\u001a\u00020\u0004H&ø\u0001\u0000\u0082\u0002\u0006\n\u0004\b!0\u0001¨\u0006\u000bÀ\u0006\u0001"}, d2 = {"Lcom/facebook/react/ViewManagerOnDemandReactPackage;", "", "getViewManagerNames", "", "", "reactContext", "Lcom/facebook/react/bridge/ReactApplicationContext;", "createViewManager", "Lcom/facebook/react/uimanager/ViewManager;", "", "viewManagerName", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public interface ViewManagerOnDemandReactPackage {
    ViewManager createViewManager(ReactApplicationContext reactContext, String viewManagerName);

    Collection<String> getViewManagerNames(ReactApplicationContext reactContext);
}
