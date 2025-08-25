package com.facebook.react.uimanager;

import com.facebook.react.bridge.NativeMap;
import com.facebook.react.bridge.RuntimeExecutor;
import com.facebook.soloader.SoLoader;
import kotlin.Metadata;
import kotlin.jvm.JvmStatic;

/* compiled from: UIConstantsProviderBinding.kt */
@Metadata(d1 = {"\u0000,\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\bÁ\u0002\u0018\u00002\u00020\u0001:\u0003\u000e\u000f\u0010B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003J)\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u00072\u0006\u0010\b\u001a\u00020\t2\u0006\u0010\n\u001a\u00020\u000b2\u0006\u0010\f\u001a\u00020\rH\u0087 ¨\u0006\u0011"}, d2 = {"Lcom/facebook/react/uimanager/UIConstantsProviderBinding;", "", "<init>", "()V", "install", "", "runtimeExecutor", "Lcom/facebook/react/bridge/RuntimeExecutor;", "defaultEventTypesProvider", "Lcom/facebook/react/uimanager/UIConstantsProviderBinding$DefaultEventTypesProvider;", "viewManagerConstantsProvider", "Lcom/facebook/react/uimanager/UIConstantsProviderBinding$ConstantsForViewManagerProvider;", "constantsProvider", "Lcom/facebook/react/uimanager/UIConstantsProviderBinding$ConstantsProvider;", "DefaultEventTypesProvider", "ConstantsForViewManagerProvider", "ConstantsProvider", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class UIConstantsProviderBinding {
    public static final UIConstantsProviderBinding INSTANCE = new UIConstantsProviderBinding();

    /* compiled from: UIConstantsProviderBinding.kt */
    @Metadata(d1 = {"\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\bg\u0018\u00002\u00020\u0001J\u0012\u0010\u0002\u001a\u0004\u0018\u00010\u00032\u0006\u0010\u0004\u001a\u00020\u0005H&ø\u0001\u0000\u0082\u0002\u0006\n\u0004\b!0\u0001¨\u0006\u0006À\u0006\u0001"}, d2 = {"Lcom/facebook/react/uimanager/UIConstantsProviderBinding$ConstantsForViewManagerProvider;", "", "getConstantsForViewManager", "Lcom/facebook/react/bridge/NativeMap;", "viewManagerName", "", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
    public interface ConstantsForViewManagerProvider {
        NativeMap getConstantsForViewManager(String viewManagerName);
    }

    /* compiled from: UIConstantsProviderBinding.kt */
    @Metadata(d1 = {"\u0000\u0010\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0000\bg\u0018\u00002\u00020\u0001J\b\u0010\u0002\u001a\u00020\u0003H&ø\u0001\u0000\u0082\u0002\u0006\n\u0004\b!0\u0001¨\u0006\u0004À\u0006\u0001"}, d2 = {"Lcom/facebook/react/uimanager/UIConstantsProviderBinding$ConstantsProvider;", "", "getConstants", "Lcom/facebook/react/bridge/NativeMap;", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
    public interface ConstantsProvider {
        NativeMap getConstants();
    }

    /* compiled from: UIConstantsProviderBinding.kt */
    @Metadata(d1 = {"\u0000\u0010\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0000\bg\u0018\u00002\u00020\u0001J\b\u0010\u0002\u001a\u00020\u0003H&ø\u0001\u0000\u0082\u0002\u0006\n\u0004\b!0\u0001¨\u0006\u0004À\u0006\u0001"}, d2 = {"Lcom/facebook/react/uimanager/UIConstantsProviderBinding$DefaultEventTypesProvider;", "", "getDefaultEventTypes", "Lcom/facebook/react/bridge/NativeMap;", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
    public interface DefaultEventTypesProvider {
        NativeMap getDefaultEventTypes();
    }

    @JvmStatic
    public static final native void install(RuntimeExecutor runtimeExecutor, DefaultEventTypesProvider defaultEventTypesProvider, ConstantsForViewManagerProvider viewManagerConstantsProvider, ConstantsProvider constantsProvider);

    private UIConstantsProviderBinding() {
    }

    static {
        SoLoader.loadLibrary("uimanagerjni");
    }
}
