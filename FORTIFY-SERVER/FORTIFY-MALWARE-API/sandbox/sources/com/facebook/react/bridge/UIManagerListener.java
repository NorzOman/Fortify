package com.facebook.react.bridge;

import com.facebook.react.common.annotations.UnstableReactNativeAPI;
import kotlin.Metadata;

/* compiled from: UIManagerListener.kt */
@Metadata(d1 = {"\u0000\u0018\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\bg\u0018\u00002\u00020\u0001J\u0010\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u0005H&J\u0010\u0010\u0006\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u0005H&J\u0010\u0010\u0007\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u0005H&J\u0010\u0010\b\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u0005H&J\u0010\u0010\t\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u0005H&ø\u0001\u0000\u0082\u0002\u0006\n\u0004\b!0\u0001¨\u0006\nÀ\u0006\u0001"}, d2 = {"Lcom/facebook/react/bridge/UIManagerListener;", "", "willDispatchViewUpdates", "", "uiManager", "Lcom/facebook/react/bridge/UIManager;", "willMountItems", "didMountItems", "didDispatchMountItems", "didScheduleMountItems", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
@UnstableReactNativeAPI
/* loaded from: classes.dex */
public interface UIManagerListener {
    void didDispatchMountItems(UIManager uiManager);

    void didMountItems(UIManager uiManager);

    void didScheduleMountItems(UIManager uiManager);

    void willDispatchViewUpdates(UIManager uiManager);

    void willMountItems(UIManager uiManager);
}
