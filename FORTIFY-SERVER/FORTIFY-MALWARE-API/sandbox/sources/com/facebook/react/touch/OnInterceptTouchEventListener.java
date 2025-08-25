package com.facebook.react.touch;

import android.view.MotionEvent;
import android.view.ViewGroup;
import androidx.core.app.NotificationCompat;
import kotlin.Metadata;

/* compiled from: OnInterceptTouchEventListener.kt */
@Metadata(d1 = {"\u0000\u001c\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\bæ\u0080\u0001\u0018\u00002\u00020\u0001J\u0018\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u0007H&ø\u0001\u0000\u0082\u0002\u0006\n\u0004\b!0\u0001¨\u0006\bÀ\u0006\u0001"}, d2 = {"Lcom/facebook/react/touch/OnInterceptTouchEventListener;", "", "onInterceptTouchEvent", "", "view", "Landroid/view/ViewGroup;", NotificationCompat.CATEGORY_EVENT, "Landroid/view/MotionEvent;", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public interface OnInterceptTouchEventListener {
    boolean onInterceptTouchEvent(ViewGroup view, MotionEvent event);
}
