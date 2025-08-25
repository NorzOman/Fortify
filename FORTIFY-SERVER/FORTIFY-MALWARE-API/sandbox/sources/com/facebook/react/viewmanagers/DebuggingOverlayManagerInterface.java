package com.facebook.react.viewmanagers;

import android.view.View;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.uimanager.ViewManagerWithGeneratedInterface;

/* loaded from: classes.dex */
public interface DebuggingOverlayManagerInterface<T extends View> extends ViewManagerWithGeneratedInterface {
    void clearElementsHighlights(T t);

    void highlightElements(T t, ReadableArray readableArray);

    void highlightTraceUpdates(T t, ReadableArray readableArray);
}
