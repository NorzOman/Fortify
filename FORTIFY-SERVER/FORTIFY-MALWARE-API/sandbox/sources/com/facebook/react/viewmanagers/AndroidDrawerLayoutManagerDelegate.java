package com.facebook.react.viewmanagers;

import android.view.View;
import com.facebook.react.bridge.ColorPropConverter;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.uimanager.BaseViewManager;
import com.facebook.react.uimanager.BaseViewManagerDelegate;
import com.facebook.react.uimanager.LayoutShadowNode;
import com.facebook.react.viewmanagers.AndroidDrawerLayoutManagerInterface;
import com.facebook.react.views.drawer.ReactDrawerLayoutManager;

/* loaded from: classes.dex */
public class AndroidDrawerLayoutManagerDelegate<T extends View, U extends BaseViewManager<T, ? extends LayoutShadowNode> & AndroidDrawerLayoutManagerInterface<T>> extends BaseViewManagerDelegate<T, U> {
    /* JADX WARN: Incorrect types in method signature: (TU;)V */
    public AndroidDrawerLayoutManagerDelegate(BaseViewManager baseViewManager) {
        super(baseViewManager);
    }

    @Override // com.facebook.react.uimanager.BaseViewManagerDelegate, com.facebook.react.uimanager.ViewManagerDelegate
    public void setProperty(T t, String str, Object obj) {
        str.hashCode();
        switch (str) {
            case "statusBarBackgroundColor":
                ((AndroidDrawerLayoutManagerInterface) this.mViewManager).setStatusBarBackgroundColor(t, ColorPropConverter.getColor(obj, t.getContext()));
                break;
            case "drawerBackgroundColor":
                ((AndroidDrawerLayoutManagerInterface) this.mViewManager).setDrawerBackgroundColor(t, ColorPropConverter.getColor(obj, t.getContext()));
                break;
            case "keyboardDismissMode":
                ((AndroidDrawerLayoutManagerInterface) this.mViewManager).setKeyboardDismissMode(t, (String) obj);
                break;
            case "drawerWidth":
                ((AndroidDrawerLayoutManagerInterface) this.mViewManager).setDrawerWidth(t, obj == null ? null : Float.valueOf(((Double) obj).floatValue()));
                break;
            case "drawerPosition":
                ((AndroidDrawerLayoutManagerInterface) this.mViewManager).setDrawerPosition(t, (String) obj);
                break;
            case "drawerLockMode":
                ((AndroidDrawerLayoutManagerInterface) this.mViewManager).setDrawerLockMode(t, (String) obj);
                break;
            default:
                super.setProperty(t, str, obj);
                break;
        }
    }

    @Override // com.facebook.react.uimanager.BaseViewManagerDelegate, com.facebook.react.uimanager.ViewManagerDelegate
    public void receiveCommand(T t, String str, ReadableArray readableArray) {
        str.hashCode();
        if (str.equals(ReactDrawerLayoutManager.COMMAND_CLOSE_DRAWER)) {
            ((AndroidDrawerLayoutManagerInterface) this.mViewManager).closeDrawer(t);
        } else if (str.equals(ReactDrawerLayoutManager.COMMAND_OPEN_DRAWER)) {
            ((AndroidDrawerLayoutManagerInterface) this.mViewManager).openDrawer(t);
        }
    }
}
