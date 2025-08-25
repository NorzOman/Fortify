package com.facebook.react.viewmanagers;

import android.view.View;
import com.facebook.react.uimanager.ViewManagerWithGeneratedInterface;

/* loaded from: classes.dex */
public interface ActivityIndicatorViewManagerInterface<T extends View> extends ViewManagerWithGeneratedInterface {
    void setAnimating(T t, boolean z);

    void setColor(T t, Integer num);

    void setHidesWhenStopped(T t, boolean z);

    void setSize(T t, String str);
}
