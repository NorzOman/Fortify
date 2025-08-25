package com.facebook.react.viewmanagers;

import android.view.View;
import com.facebook.react.bridge.ColorPropConverter;
import com.facebook.react.uimanager.BaseViewManager;
import com.facebook.react.uimanager.BaseViewManagerDelegate;
import com.facebook.react.uimanager.LayoutShadowNode;
import com.facebook.react.uimanager.ViewProps;
import com.facebook.react.viewmanagers.RNSScreenStackHeaderConfigManagerInterface;

/* loaded from: classes.dex */
public class RNSScreenStackHeaderConfigManagerDelegate<T extends View, U extends BaseViewManager<T, ? extends LayoutShadowNode> & RNSScreenStackHeaderConfigManagerInterface<T>> extends BaseViewManagerDelegate<T, U> {
    /* JADX WARN: Incorrect types in method signature: (TU;)V */
    public RNSScreenStackHeaderConfigManagerDelegate(BaseViewManager baseViewManager) {
        super(baseViewManager);
    }

    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    @Override // com.facebook.react.uimanager.BaseViewManagerDelegate, com.facebook.react.uimanager.ViewManagerDelegate
    public void setProperty(T t, String str, Object obj) {
        str.hashCode();
        char c = 65535;
        switch (str.hashCode()) {
            case -1822687399:
                if (str.equals("translucent")) {
                    c = 0;
                    break;
                }
                break;
            case -1799367701:
                if (str.equals("titleColor")) {
                    c = 1;
                    break;
                }
                break;
            case -1795707688:
                if (str.equals("blurEffect")) {
                    c = 2;
                    break;
                }
                break;
            case -1774658170:
                if (str.equals("largeTitleColor")) {
                    c = 3;
                    break;
                }
                break;
            case -1715368693:
                if (str.equals("titleFontFamily")) {
                    c = 4;
                    break;
                }
                break;
            case -1503810304:
                if (str.equals("disableBackButtonMenu")) {
                    c = 5;
                    break;
                }
                break;
            case -1225100257:
                if (str.equals("titleFontWeight")) {
                    c = 6;
                    break;
                }
                break;
            case -1217487446:
                if (str.equals(ViewProps.HIDDEN)) {
                    c = 7;
                    break;
                }
                break;
            case -1094575123:
                if (str.equals("largeTitleFontSize")) {
                    c = '\b';
                    break;
                }
                break;
            case -1093089076:
                if (str.equals("backButtonDisplayMode")) {
                    c = '\t';
                    break;
                }
                break;
            case -1063138943:
                if (str.equals("backTitleVisible")) {
                    c = '\n';
                    break;
                }
                break;
            case -962590849:
                if (str.equals("direction")) {
                    c = 11;
                    break;
                }
                break;
            case -389245640:
                if (str.equals("largeTitleBackgroundColor")) {
                    c = '\f';
                    break;
                }
                break;
            case -140063148:
                if (str.equals("backButtonInCustomView")) {
                    c = '\r';
                    break;
                }
                break;
            case 347216:
                if (str.equals("largeTitleFontFamily")) {
                    c = 14;
                    break;
                }
                break;
            case 94842723:
                if (str.equals(ViewProps.COLOR)) {
                    c = 15;
                    break;
                }
                break;
            case 110371416:
                if (str.equals("title")) {
                    c = 16;
                    break;
                }
                break;
            case 183888321:
                if (str.equals("backTitleFontSize")) {
                    c = 17;
                    break;
                }
                break;
            case 243070244:
                if (str.equals("backTitleFontFamily")) {
                    c = 18;
                    break;
                }
                break;
            case 339462402:
                if (str.equals("hideShadow")) {
                    c = 19;
                    break;
                }
                break;
            case 490615652:
                if (str.equals("largeTitleFontWeight")) {
                    c = 20;
                    break;
                }
                break;
            case 1038753243:
                if (str.equals("hideBackButton")) {
                    c = 21;
                    break;
                }
                break;
            case 1287124693:
                if (str.equals(ViewProps.BACKGROUND_COLOR)) {
                    c = 22;
                    break;
                }
                break;
            case 1324688817:
                if (str.equals("backTitle")) {
                    c = 23;
                    break;
                }
                break;
            case 1518161768:
                if (str.equals("titleFontSize")) {
                    c = 24;
                    break;
                }
                break;
            case 1564506303:
                if (str.equals("largeTitleHideShadow")) {
                    c = 25;
                    break;
                }
                break;
            case 2029798365:
                if (str.equals("largeTitle")) {
                    c = 26;
                    break;
                }
                break;
            case 2099541337:
                if (str.equals("topInsetEnabled")) {
                    c = 27;
                    break;
                }
                break;
        }
        switch (c) {
            case 0:
                ((RNSScreenStackHeaderConfigManagerInterface) this.mViewManager).setTranslucent(t, obj != null ? ((Boolean) obj).booleanValue() : false);
                break;
            case 1:
                ((RNSScreenStackHeaderConfigManagerInterface) this.mViewManager).setTitleColor(t, ColorPropConverter.getColor(obj, t.getContext()));
                break;
            case 2:
                ((RNSScreenStackHeaderConfigManagerInterface) this.mViewManager).setBlurEffect(t, (String) obj);
                break;
            case 3:
                ((RNSScreenStackHeaderConfigManagerInterface) this.mViewManager).setLargeTitleColor(t, ColorPropConverter.getColor(obj, t.getContext()));
                break;
            case 4:
                ((RNSScreenStackHeaderConfigManagerInterface) this.mViewManager).setTitleFontFamily(t, obj != null ? (String) obj : null);
                break;
            case 5:
                ((RNSScreenStackHeaderConfigManagerInterface) this.mViewManager).setDisableBackButtonMenu(t, obj != null ? ((Boolean) obj).booleanValue() : false);
                break;
            case 6:
                ((RNSScreenStackHeaderConfigManagerInterface) this.mViewManager).setTitleFontWeight(t, obj != null ? (String) obj : null);
                break;
            case 7:
                ((RNSScreenStackHeaderConfigManagerInterface) this.mViewManager).setHidden(t, obj != null ? ((Boolean) obj).booleanValue() : false);
                break;
            case '\b':
                ((RNSScreenStackHeaderConfigManagerInterface) this.mViewManager).setLargeTitleFontSize(t, obj != null ? ((Double) obj).intValue() : 0);
                break;
            case '\t':
                ((RNSScreenStackHeaderConfigManagerInterface) this.mViewManager).setBackButtonDisplayMode(t, (String) obj);
                break;
            case '\n':
                ((RNSScreenStackHeaderConfigManagerInterface) this.mViewManager).setBackTitleVisible(t, obj != null ? ((Boolean) obj).booleanValue() : true);
                break;
            case 11:
                ((RNSScreenStackHeaderConfigManagerInterface) this.mViewManager).setDirection(t, (String) obj);
                break;
            case '\f':
                ((RNSScreenStackHeaderConfigManagerInterface) this.mViewManager).setLargeTitleBackgroundColor(t, ColorPropConverter.getColor(obj, t.getContext()));
                break;
            case '\r':
                ((RNSScreenStackHeaderConfigManagerInterface) this.mViewManager).setBackButtonInCustomView(t, obj != null ? ((Boolean) obj).booleanValue() : false);
                break;
            case 14:
                ((RNSScreenStackHeaderConfigManagerInterface) this.mViewManager).setLargeTitleFontFamily(t, obj != null ? (String) obj : null);
                break;
            case 15:
                ((RNSScreenStackHeaderConfigManagerInterface) this.mViewManager).setColor(t, ColorPropConverter.getColor(obj, t.getContext()));
                break;
            case 16:
                ((RNSScreenStackHeaderConfigManagerInterface) this.mViewManager).setTitle(t, obj != null ? (String) obj : null);
                break;
            case 17:
                ((RNSScreenStackHeaderConfigManagerInterface) this.mViewManager).setBackTitleFontSize(t, obj != null ? ((Double) obj).intValue() : 0);
                break;
            case 18:
                ((RNSScreenStackHeaderConfigManagerInterface) this.mViewManager).setBackTitleFontFamily(t, obj != null ? (String) obj : null);
                break;
            case 19:
                ((RNSScreenStackHeaderConfigManagerInterface) this.mViewManager).setHideShadow(t, obj != null ? ((Boolean) obj).booleanValue() : false);
                break;
            case 20:
                ((RNSScreenStackHeaderConfigManagerInterface) this.mViewManager).setLargeTitleFontWeight(t, obj != null ? (String) obj : null);
                break;
            case 21:
                ((RNSScreenStackHeaderConfigManagerInterface) this.mViewManager).setHideBackButton(t, obj != null ? ((Boolean) obj).booleanValue() : false);
                break;
            case 22:
                ((RNSScreenStackHeaderConfigManagerInterface) this.mViewManager).setBackgroundColor(t, ColorPropConverter.getColor(obj, t.getContext()));
                break;
            case 23:
                ((RNSScreenStackHeaderConfigManagerInterface) this.mViewManager).setBackTitle(t, obj != null ? (String) obj : null);
                break;
            case 24:
                ((RNSScreenStackHeaderConfigManagerInterface) this.mViewManager).setTitleFontSize(t, obj != null ? ((Double) obj).intValue() : 0);
                break;
            case 25:
                ((RNSScreenStackHeaderConfigManagerInterface) this.mViewManager).setLargeTitleHideShadow(t, obj != null ? ((Boolean) obj).booleanValue() : false);
                break;
            case 26:
                ((RNSScreenStackHeaderConfigManagerInterface) this.mViewManager).setLargeTitle(t, obj != null ? ((Boolean) obj).booleanValue() : false);
                break;
            case 27:
                ((RNSScreenStackHeaderConfigManagerInterface) this.mViewManager).setTopInsetEnabled(t, obj != null ? ((Boolean) obj).booleanValue() : false);
                break;
            default:
                super.setProperty(t, str, obj);
                break;
        }
    }
}
