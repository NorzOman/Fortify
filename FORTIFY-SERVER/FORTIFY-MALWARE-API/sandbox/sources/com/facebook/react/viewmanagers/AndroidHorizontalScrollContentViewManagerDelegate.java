package com.facebook.react.viewmanagers;

import android.view.View;
import com.facebook.react.uimanager.BaseViewManager;
import com.facebook.react.uimanager.BaseViewManagerDelegate;
import com.facebook.react.uimanager.LayoutShadowNode;
import com.facebook.react.uimanager.ReactClippingViewGroupHelper;
import com.facebook.react.viewmanagers.AndroidHorizontalScrollContentViewManagerInterface;

/* loaded from: classes.dex */
public class AndroidHorizontalScrollContentViewManagerDelegate<T extends View, U extends BaseViewManager<T, ? extends LayoutShadowNode> & AndroidHorizontalScrollContentViewManagerInterface<T>> extends BaseViewManagerDelegate<T, U> {
    /* JADX WARN: Incorrect types in method signature: (TU;)V */
    public AndroidHorizontalScrollContentViewManagerDelegate(BaseViewManager baseViewManager) {
        super(baseViewManager);
    }

    @Override // com.facebook.react.uimanager.BaseViewManagerDelegate, com.facebook.react.uimanager.ViewManagerDelegate
    public void setProperty(T t, String str, Object obj) {
        str.hashCode();
        if (str.equals(ReactClippingViewGroupHelper.PROP_REMOVE_CLIPPED_SUBVIEWS)) {
            ((AndroidHorizontalScrollContentViewManagerInterface) this.mViewManager).setRemoveClippedSubviews(t, obj == null ? false : ((Boolean) obj).booleanValue());
        } else {
            super.setProperty(t, str, obj);
        }
    }
}
