package com.facebook.react.uimanager.events;

import android.view.MotionEvent;
import android.view.View;
import androidx.core.app.NotificationCompat;
import com.facebook.react.uimanager.RootView;
import com.facebook.react.uimanager.RootViewUtil;
import kotlin.Metadata;
import kotlin.jvm.JvmStatic;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: NativeGestureUtil.kt */
@Metadata(d1 = {"\u0000 \n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\bÆ\u0002\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003J\u0018\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u00072\u0006\u0010\b\u001a\u00020\tH\u0007J\u0018\u0010\n\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u00072\u0006\u0010\b\u001a\u00020\tH\u0007¨\u0006\u000b"}, d2 = {"Lcom/facebook/react/uimanager/events/NativeGestureUtil;", "", "<init>", "()V", "notifyNativeGestureStarted", "", "view", "Landroid/view/View;", NotificationCompat.CATEGORY_EVENT, "Landroid/view/MotionEvent;", "notifyNativeGestureEnded", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class NativeGestureUtil {
    public static final NativeGestureUtil INSTANCE = new NativeGestureUtil();

    private NativeGestureUtil() {
    }

    @JvmStatic
    public static final void notifyNativeGestureStarted(View view, MotionEvent event) {
        Intrinsics.checkNotNullParameter(view, "view");
        Intrinsics.checkNotNullParameter(event, "event");
        RootView rootView = RootViewUtil.getRootView(view);
        if (rootView != null) {
            rootView.onChildStartedNativeGesture(view, event);
        }
    }

    @JvmStatic
    public static final void notifyNativeGestureEnded(View view, MotionEvent event) {
        Intrinsics.checkNotNullParameter(view, "view");
        Intrinsics.checkNotNullParameter(event, "event");
        RootView rootView = RootViewUtil.getRootView(view);
        if (rootView != null) {
            rootView.onChildEndedNativeGesture(view, event);
        }
    }
}
