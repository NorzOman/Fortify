package com.facebook.react.viewmanagers;

import android.view.View;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.uimanager.BaseViewManager;
import com.facebook.react.uimanager.BaseViewManagerDelegate;
import com.facebook.react.uimanager.LayoutShadowNode;
import com.facebook.react.viewmanagers.ModalHostViewManagerInterface;

/* loaded from: classes.dex */
public class ModalHostViewManagerDelegate<T extends View, U extends BaseViewManager<T, ? extends LayoutShadowNode> & ModalHostViewManagerInterface<T>> extends BaseViewManagerDelegate<T, U> {
    /* JADX WARN: Incorrect types in method signature: (TU;)V */
    public ModalHostViewManagerDelegate(BaseViewManager baseViewManager) {
        super(baseViewManager);
    }

    @Override // com.facebook.react.uimanager.BaseViewManagerDelegate, com.facebook.react.uimanager.ViewManagerDelegate
    public void setProperty(T t, String str, Object obj) {
        str.hashCode();
        switch (str) {
            case "presentationStyle":
                ((ModalHostViewManagerInterface) this.mViewManager).setPresentationStyle(t, (String) obj);
                break;
            case "supportedOrientations":
                ((ModalHostViewManagerInterface) this.mViewManager).setSupportedOrientations(t, (ReadableArray) obj);
                break;
            case "transparent":
                ((ModalHostViewManagerInterface) this.mViewManager).setTransparent(t, obj != null ? ((Boolean) obj).booleanValue() : false);
                break;
            case "identifier":
                ((ModalHostViewManagerInterface) this.mViewManager).setIdentifier(t, obj != null ? ((Double) obj).intValue() : 0);
                break;
            case "statusBarTranslucent":
                ((ModalHostViewManagerInterface) this.mViewManager).setStatusBarTranslucent(t, obj != null ? ((Boolean) obj).booleanValue() : false);
                break;
            case "animated":
                ((ModalHostViewManagerInterface) this.mViewManager).setAnimated(t, obj != null ? ((Boolean) obj).booleanValue() : false);
                break;
            case "visible":
                ((ModalHostViewManagerInterface) this.mViewManager).setVisible(t, obj != null ? ((Boolean) obj).booleanValue() : false);
                break;
            case "navigationBarTranslucent":
                ((ModalHostViewManagerInterface) this.mViewManager).setNavigationBarTranslucent(t, obj != null ? ((Boolean) obj).booleanValue() : false);
                break;
            case "hardwareAccelerated":
                ((ModalHostViewManagerInterface) this.mViewManager).setHardwareAccelerated(t, obj != null ? ((Boolean) obj).booleanValue() : false);
                break;
            case "animationType":
                ((ModalHostViewManagerInterface) this.mViewManager).setAnimationType(t, (String) obj);
                break;
            default:
                super.setProperty(t, str, obj);
                break;
        }
    }
}
