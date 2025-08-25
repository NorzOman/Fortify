package com.facebook.react.viewmanagers;

import android.view.View;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.uimanager.ViewManagerWithGeneratedInterface;

/* loaded from: classes.dex */
public interface RNCSafeAreaViewManagerInterface<T extends View> extends ViewManagerWithGeneratedInterface {
    void setEdges(T t, ReadableMap readableMap);

    void setMode(T t, String str);
}
