package com.facebook.react.viewmanagers;

import android.view.View;
import com.facebook.react.uimanager.ViewManagerWithGeneratedInterface;

/* loaded from: classes.dex */
public interface AndroidDrawerLayoutManagerInterface<T extends View> extends ViewManagerWithGeneratedInterface {
    void closeDrawer(T t);

    void openDrawer(T t);

    void setDrawerBackgroundColor(T t, Integer num);

    void setDrawerLockMode(T t, String str);

    void setDrawerPosition(T t, String str);

    void setDrawerWidth(T t, Float f);

    void setKeyboardDismissMode(T t, String str);

    void setStatusBarBackgroundColor(T t, Integer num);
}
