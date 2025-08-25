package com.facebook.react.touch;

import android.view.MotionEvent;
import android.view.ViewGroup;
import android.view.ViewParent;
import androidx.core.app.NotificationCompat;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: JSResponderHandler.kt */
@Metadata(d1 = {"\u00004\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\b\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0004\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\u0018\u0000 \u00132\u00020\u0001:\u0001\u0013B\u0007¢\u0006\u0004\b\u0002\u0010\u0003J\u0018\u0010\b\u001a\u00020\t2\u0006\u0010\n\u001a\u00020\u00052\b\u0010\u0006\u001a\u0004\u0018\u00010\u0007J\u0006\u0010\u000b\u001a\u00020\tJ\b\u0010\f\u001a\u00020\tH\u0002J\u0018\u0010\r\u001a\u00020\u000e2\u0006\u0010\u000f\u001a\u00020\u00102\u0006\u0010\u0011\u001a\u00020\u0012H\u0016R\u000e\u0010\u0004\u001a\u00020\u0005X\u0082\u000e¢\u0006\u0002\n\u0000R\u0010\u0010\u0006\u001a\u0004\u0018\u00010\u0007X\u0082\u000e¢\u0006\u0002\n\u0000¨\u0006\u0014"}, d2 = {"Lcom/facebook/react/touch/JSResponderHandler;", "Lcom/facebook/react/touch/OnInterceptTouchEventListener;", "<init>", "()V", "currentJSResponder", "", "viewParentBlockingNativeResponder", "Landroid/view/ViewParent;", "setJSResponder", "", "tag", "clearJSResponder", "maybeUnblockNativeResponder", "onInterceptTouchEvent", "", "view", "Landroid/view/ViewGroup;", NotificationCompat.CATEGORY_EVENT, "Landroid/view/MotionEvent;", "Companion", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class JSResponderHandler implements OnInterceptTouchEventListener {
    private static final Companion Companion = new Companion(null);
    private static final int JS_RESPONDER_UNSET = -1;
    private volatile int currentJSResponder = -1;
    private ViewParent viewParentBlockingNativeResponder;

    public final void setJSResponder(int tag, ViewParent viewParentBlockingNativeResponder) {
        this.currentJSResponder = tag;
        maybeUnblockNativeResponder();
        if (viewParentBlockingNativeResponder != null) {
            viewParentBlockingNativeResponder.requestDisallowInterceptTouchEvent(true);
            this.viewParentBlockingNativeResponder = viewParentBlockingNativeResponder;
        }
    }

    public final void clearJSResponder() {
        this.currentJSResponder = -1;
        maybeUnblockNativeResponder();
    }

    private final void maybeUnblockNativeResponder() {
        ViewParent viewParent = this.viewParentBlockingNativeResponder;
        if (viewParent != null) {
            viewParent.requestDisallowInterceptTouchEvent(false);
        }
        this.viewParentBlockingNativeResponder = null;
    }

    @Override // com.facebook.react.touch.OnInterceptTouchEventListener
    public boolean onInterceptTouchEvent(ViewGroup view, MotionEvent event) {
        Intrinsics.checkNotNullParameter(view, "view");
        Intrinsics.checkNotNullParameter(event, "event");
        int i = this.currentJSResponder;
        return (i == -1 || event.getAction() == 1 || view.getId() != i) ? false : true;
    }

    /* compiled from: JSResponderHandler.kt */
    @Metadata(d1 = {"\u0000\u0012\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0010\b\n\u0000\b\u0082\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003R\u000e\u0010\u0004\u001a\u00020\u0005X\u0082T¢\u0006\u0002\n\u0000¨\u0006\u0006"}, d2 = {"Lcom/facebook/react/touch/JSResponderHandler$Companion;", "", "<init>", "()V", "JS_RESPONDER_UNSET", "", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
    private static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }
    }
}
