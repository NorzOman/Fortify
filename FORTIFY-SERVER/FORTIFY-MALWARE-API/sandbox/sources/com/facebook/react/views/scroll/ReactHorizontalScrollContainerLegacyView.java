package com.facebook.react.views.scroll;

import android.content.Context;
import com.facebook.react.modules.i18nmanager.I18nUtil;
import com.facebook.react.uimanager.ReactClippingViewGroupHelper;
import com.facebook.react.uimanager.ViewProps;
import com.facebook.react.views.view.ReactViewGroup;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: ReactHorizontalScrollContainerLegacyView.kt */
@Metadata(d1 = {"\u0000(\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0004\n\u0002\u0010\b\n\u0002\b\u0004\b\u0000\u0018\u00002\u00020\u0001B\u000f\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0004\b\u0004\u0010\u0005J\u0010\u0010\b\u001a\u00020\t2\u0006\u0010\n\u001a\u00020\u0007H\u0016J0\u0010\u000b\u001a\u00020\t2\u0006\u0010\f\u001a\u00020\u00072\u0006\u0010\r\u001a\u00020\u000e2\u0006\u0010\u000f\u001a\u00020\u000e2\u0006\u0010\u0010\u001a\u00020\u000e2\u0006\u0010\u0011\u001a\u00020\u000eH\u0014R\u000e\u0010\u0006\u001a\u00020\u0007X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\u0012"}, d2 = {"Lcom/facebook/react/views/scroll/ReactHorizontalScrollContainerLegacyView;", "Lcom/facebook/react/views/view/ReactViewGroup;", "context", "Landroid/content/Context;", "<init>", "(Landroid/content/Context;)V", "isRTL", "", "setRemoveClippedSubviews", "", ReactClippingViewGroupHelper.PROP_REMOVE_CLIPPED_SUBVIEWS, "onLayout", "changed", ViewProps.LEFT, "", ViewProps.TOP, ViewProps.RIGHT, ViewProps.BOTTOM, "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class ReactHorizontalScrollContainerLegacyView extends ReactViewGroup {
    private final boolean isRTL;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public ReactHorizontalScrollContainerLegacyView(Context context) {
        super(context);
        Intrinsics.checkNotNullParameter(context, "context");
        this.isRTL = I18nUtil.INSTANCE.getInstance().isRTL(context);
    }

    @Override // com.facebook.react.views.view.ReactViewGroup, com.facebook.react.uimanager.ReactClippingViewGroup
    public void setRemoveClippedSubviews(boolean removeClippedSubviews) {
        if (this.isRTL) {
            super.setRemoveClippedSubviews(false);
        } else {
            super.setRemoveClippedSubviews(removeClippedSubviews);
        }
    }

    @Override // com.facebook.react.views.view.ReactViewGroup, android.view.ViewGroup, android.view.View
    protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
        if (this.isRTL) {
            setLeft(0);
            setTop(top);
            setRight(right - left);
            setBottom(bottom);
        }
    }
}
