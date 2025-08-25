package com.facebook.react.viewmanagers;

import android.view.View;
import com.facebook.react.uimanager.ViewManagerWithGeneratedInterface;

/* loaded from: classes.dex */
public interface RNGestureHandlerButtonManagerInterface<T extends View> extends ViewManagerWithGeneratedInterface {
    void setBorderColor(T t, Integer num);

    void setBorderStyle(T t, String str);

    void setBorderWidth(T t, float f);

    void setBorderless(T t, boolean z);

    void setEnabled(T t, boolean z);

    void setExclusive(T t, boolean z);

    void setForeground(T t, boolean z);

    void setRippleColor(T t, Integer num);

    void setRippleRadius(T t, int i);

    void setTouchSoundDisabled(T t, boolean z);
}
