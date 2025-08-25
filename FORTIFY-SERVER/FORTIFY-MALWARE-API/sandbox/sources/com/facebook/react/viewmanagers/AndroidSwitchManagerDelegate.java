package com.facebook.react.viewmanagers;

import android.view.View;
import com.facebook.react.bridge.ColorPropConverter;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.uimanager.BaseViewManager;
import com.facebook.react.uimanager.BaseViewManagerDelegate;
import com.facebook.react.uimanager.LayoutShadowNode;
import com.facebook.react.viewmanagers.AndroidSwitchManagerInterface;

/* loaded from: classes.dex */
public class AndroidSwitchManagerDelegate<T extends View, U extends BaseViewManager<T, ? extends LayoutShadowNode> & AndroidSwitchManagerInterface<T>> extends BaseViewManagerDelegate<T, U> {
    /* JADX WARN: Incorrect types in method signature: (TU;)V */
    public AndroidSwitchManagerDelegate(BaseViewManager baseViewManager) {
        super(baseViewManager);
    }

    @Override // com.facebook.react.uimanager.BaseViewManagerDelegate, com.facebook.react.uimanager.ViewManagerDelegate
    public void setProperty(T t, String str, Object obj) {
        str.hashCode();
        switch (str) {
            case "thumbColor":
                ((AndroidSwitchManagerInterface) this.mViewManager).setThumbColor(t, ColorPropConverter.getColor(obj, t.getContext()));
                break;
            case "enabled":
                ((AndroidSwitchManagerInterface) this.mViewManager).setEnabled(t, obj != null ? ((Boolean) obj).booleanValue() : true);
                break;
            case "trackTintColor":
                ((AndroidSwitchManagerInterface) this.mViewManager).setTrackTintColor(t, ColorPropConverter.getColor(obj, t.getContext()));
                break;
            case "on":
                ((AndroidSwitchManagerInterface) this.mViewManager).setOn(t, obj != null ? ((Boolean) obj).booleanValue() : false);
                break;
            case "value":
                ((AndroidSwitchManagerInterface) this.mViewManager).setValue(t, obj != null ? ((Boolean) obj).booleanValue() : false);
                break;
            case "disabled":
                ((AndroidSwitchManagerInterface) this.mViewManager).setDisabled(t, obj != null ? ((Boolean) obj).booleanValue() : false);
                break;
            case "trackColorForFalse":
                ((AndroidSwitchManagerInterface) this.mViewManager).setTrackColorForFalse(t, ColorPropConverter.getColor(obj, t.getContext()));
                break;
            case "thumbTintColor":
                ((AndroidSwitchManagerInterface) this.mViewManager).setThumbTintColor(t, ColorPropConverter.getColor(obj, t.getContext()));
                break;
            case "trackColorForTrue":
                ((AndroidSwitchManagerInterface) this.mViewManager).setTrackColorForTrue(t, ColorPropConverter.getColor(obj, t.getContext()));
                break;
            default:
                super.setProperty(t, str, obj);
                break;
        }
    }

    @Override // com.facebook.react.uimanager.BaseViewManagerDelegate, com.facebook.react.uimanager.ViewManagerDelegate
    public void receiveCommand(T t, String str, ReadableArray readableArray) {
        str.hashCode();
        if (str.equals("setNativeValue")) {
            ((AndroidSwitchManagerInterface) this.mViewManager).setNativeValue(t, readableArray.getBoolean(0));
        }
    }
}
