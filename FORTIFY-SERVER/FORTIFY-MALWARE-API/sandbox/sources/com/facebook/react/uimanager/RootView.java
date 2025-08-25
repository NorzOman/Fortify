package com.facebook.react.uimanager;

import android.view.MotionEvent;
import android.view.View;
import kotlin.Deprecated;
import kotlin.Metadata;
import kotlin.ReplaceWith;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: RootView.kt */
@Metadata(d1 = {"\u0000$\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u0003\n\u0000\bf\u0018\u00002\u00020\u0001J\u001a\u0010\u0002\u001a\u00020\u00032\b\u0010\u0004\u001a\u0004\u0018\u00010\u00052\u0006\u0010\u0006\u001a\u00020\u0007H&J\u0010\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0006\u001a\u00020\u0007H\u0017J\u0018\u0010\b\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u0007H&J\u0010\u0010\t\u001a\u00020\u00032\u0006\u0010\n\u001a\u00020\u000bH&ø\u0001\u0000\u0082\u0002\u0006\n\u0004\b!0\u0001¨\u0006\fÀ\u0006\u0001"}, d2 = {"Lcom/facebook/react/uimanager/RootView;", "", "onChildStartedNativeGesture", "", "childView", "Landroid/view/View;", "ev", "Landroid/view/MotionEvent;", "onChildEndedNativeGesture", "handleException", "t", "", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public interface RootView {
    void handleException(Throwable t);

    void onChildEndedNativeGesture(View childView, MotionEvent ev);

    void onChildStartedNativeGesture(View childView, MotionEvent ev);

    @Deprecated(message = "Use onChildStartedNativeGesture with a childView parameter.", replaceWith = @ReplaceWith(expression = "onChildStartedNativeGesture", imports = {}))
    default void onChildStartedNativeGesture(MotionEvent ev) {
        Intrinsics.checkNotNullParameter(ev, "ev");
        onChildStartedNativeGesture(null, ev);
    }
}
