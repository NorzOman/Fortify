package com.facebook.react.viewmanagers;

import android.view.View;
import com.facebook.react.bridge.ColorPropConverter;
import com.facebook.react.uimanager.BaseViewManager;
import com.facebook.react.uimanager.BaseViewManagerDelegate;
import com.facebook.react.uimanager.LayoutShadowNode;
import com.facebook.react.viewmanagers.ActivityIndicatorViewManagerInterface;

/* loaded from: classes.dex */
public class ActivityIndicatorViewManagerDelegate<T extends View, U extends BaseViewManager<T, ? extends LayoutShadowNode> & ActivityIndicatorViewManagerInterface<T>> extends BaseViewManagerDelegate<T, U> {
    /* JADX WARN: Incorrect types in method signature: (TU;)V */
    public ActivityIndicatorViewManagerDelegate(BaseViewManager baseViewManager) {
        super(baseViewManager);
    }

    @Override // com.facebook.react.uimanager.BaseViewManagerDelegate, com.facebook.react.uimanager.ViewManagerDelegate
    public void setProperty(T t, String str, Object obj) {
        str.hashCode();
        switch (str) {
            case "size":
                ((ActivityIndicatorViewManagerInterface) this.mViewManager).setSize(t, (String) obj);
                break;
            case "color":
                ((ActivityIndicatorViewManagerInterface) this.mViewManager).setColor(t, ColorPropConverter.getColor(obj, t.getContext()));
                break;
            case "hidesWhenStopped":
                ((ActivityIndicatorViewManagerInterface) this.mViewManager).setHidesWhenStopped(t, obj != null ? ((Boolean) obj).booleanValue() : true);
                break;
            case "animating":
                ((ActivityIndicatorViewManagerInterface) this.mViewManager).setAnimating(t, obj != null ? ((Boolean) obj).booleanValue() : true);
                break;
            default:
                super.setProperty(t, str, obj);
                break;
        }
    }
}
