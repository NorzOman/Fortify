package com.facebook.react.views.view;

import android.view.View;
import com.facebook.react.bridge.UiThreadUtil;
import com.facebook.react.uimanager.ReactClippingViewGroupHelper;
import com.facebook.react.uimanager.ViewGroupManager;
import com.facebook.react.uimanager.annotations.ReactProp;
import com.facebook.react.views.view.ReactViewGroup;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: ReactClippingViewManager.kt */
@Metadata(d1 = {"\u00000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0002\b\n\b&\u0018\u0000*\b\b\u0000\u0010\u0001*\u00020\u00022\b\u0012\u0004\u0012\u0002H\u00010\u0003B\u0007¢\u0006\u0004\b\u0004\u0010\u0005J\u001d\u0010\u0006\u001a\u00020\u00072\u0006\u0010\b\u001a\u00028\u00002\u0006\u0010\t\u001a\u00020\nH\u0017¢\u0006\u0002\u0010\u000bJ%\u0010\f\u001a\u00020\u00072\u0006\u0010\r\u001a\u00028\u00002\u0006\u0010\u000e\u001a\u00020\u000f2\u0006\u0010\u0010\u001a\u00020\u0011H\u0016¢\u0006\u0002\u0010\u0012J\u0015\u0010\u0013\u001a\u00020\u00112\u0006\u0010\r\u001a\u00028\u0000H\u0016¢\u0006\u0002\u0010\u0014J\u001f\u0010\u0015\u001a\u0004\u0018\u00010\u000f2\u0006\u0010\r\u001a\u00028\u00002\u0006\u0010\u0010\u001a\u00020\u0011H\u0016¢\u0006\u0002\u0010\u0016J\u001d\u0010\u0017\u001a\u00020\u00072\u0006\u0010\r\u001a\u00028\u00002\u0006\u0010\u0010\u001a\u00020\u0011H\u0016¢\u0006\u0002\u0010\u0018J\u0015\u0010\u0019\u001a\u00020\u00072\u0006\u0010\r\u001a\u00028\u0000H\u0016¢\u0006\u0002\u0010\u001a¨\u0006\u001b"}, d2 = {"Lcom/facebook/react/views/view/ReactClippingViewManager;", "T", "Lcom/facebook/react/views/view/ReactViewGroup;", "Lcom/facebook/react/uimanager/ViewGroupManager;", "<init>", "()V", "setRemoveClippedSubviews", "", "view", ReactClippingViewGroupHelper.PROP_REMOVE_CLIPPED_SUBVIEWS, "", "(Lcom/facebook/react/views/view/ReactViewGroup;Z)V", "addView", "parent", "child", "Landroid/view/View;", "index", "", "(Lcom/facebook/react/views/view/ReactViewGroup;Landroid/view/View;I)V", "getChildCount", "(Lcom/facebook/react/views/view/ReactViewGroup;)I", "getChildAt", "(Lcom/facebook/react/views/view/ReactViewGroup;I)Landroid/view/View;", "removeViewAt", "(Lcom/facebook/react/views/view/ReactViewGroup;I)V", "removeAllViews", "(Lcom/facebook/react/views/view/ReactViewGroup;)V", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public abstract class ReactClippingViewManager<T extends ReactViewGroup> extends ViewGroupManager<T> {
    @ReactProp(name = ReactClippingViewGroupHelper.PROP_REMOVE_CLIPPED_SUBVIEWS)
    public void setRemoveClippedSubviews(T view, boolean removeClippedSubviews) {
        Intrinsics.checkNotNullParameter(view, "view");
        UiThreadUtil.assertOnUiThread();
        view.setRemoveClippedSubviews(removeClippedSubviews);
    }

    @Override // com.facebook.react.uimanager.ViewGroupManager
    public void addView(T parent, View child, int index) {
        Intrinsics.checkNotNullParameter(parent, "parent");
        Intrinsics.checkNotNullParameter(child, "child");
        UiThreadUtil.assertOnUiThread();
        if (parent.getRemoveClippedSubviews()) {
            parent.addViewWithSubviewClippingEnabled(child, index);
        } else {
            parent.addView(child, index);
        }
    }

    @Override // com.facebook.react.uimanager.ViewGroupManager
    public int getChildCount(T parent) {
        Intrinsics.checkNotNullParameter(parent, "parent");
        if (parent.getRemoveClippedSubviews()) {
            return parent.getAllChildrenCount();
        }
        return parent.getChildCount();
    }

    @Override // com.facebook.react.uimanager.ViewGroupManager
    public View getChildAt(T parent, int index) {
        Intrinsics.checkNotNullParameter(parent, "parent");
        if (parent.getRemoveClippedSubviews()) {
            return parent.getChildAtWithSubviewClippingEnabled(index);
        }
        return parent.getChildAt(index);
    }

    @Override // com.facebook.react.uimanager.ViewGroupManager
    public void removeViewAt(T parent, int index) {
        Intrinsics.checkNotNullParameter(parent, "parent");
        UiThreadUtil.assertOnUiThread();
        if (parent.getRemoveClippedSubviews()) {
            View childAt = getChildAt((ReactClippingViewManager<T>) parent, index);
            if (childAt != null) {
                parent.removeViewWithSubviewClippingEnabled(childAt);
                return;
            }
            return;
        }
        parent.removeViewAt(index);
    }

    @Override // com.facebook.react.uimanager.IViewGroupManager
    public void removeAllViews(T parent) {
        Intrinsics.checkNotNullParameter(parent, "parent");
        UiThreadUtil.assertOnUiThread();
        if (parent.getRemoveClippedSubviews()) {
            parent.removeAllViewsWithSubviewClippingEnabled();
        } else {
            parent.removeAllViews();
        }
    }
}
