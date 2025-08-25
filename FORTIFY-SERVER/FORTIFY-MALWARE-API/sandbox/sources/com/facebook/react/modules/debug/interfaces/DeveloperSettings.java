package com.facebook.react.modules.debug.interfaces;

import com.facebook.react.packagerconnection.PackagerConnectionSettings;
import kotlin.Deprecated;
import kotlin.Metadata;

/* compiled from: DeveloperSettings.kt */
@Metadata(d1 = {"\u0000&\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0002\b\u0016\n\u0002\u0010\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\bf\u0018\u00002\u00020\u0001J\u0010\u0010\u001d\u001a\u00020\u001e2\u0006\u0010\u001f\u001a\u00020 H&R\u0012\u0010\u0002\u001a\u00020\u0003X¦\u0004¢\u0006\u0006\u001a\u0004\b\u0004\u0010\u0005R\u0018\u0010\u0006\u001a\u00020\u0007X¦\u000e¢\u0006\f\u001a\u0004\b\u0006\u0010\b\"\u0004\b\t\u0010\nR\u0018\u0010\u000b\u001a\u00020\u0007X¦\u000e¢\u0006\f\u001a\u0004\b\u000b\u0010\b\"\u0004\b\f\u0010\nR\u0018\u0010\r\u001a\u00020\u0007X¦\u000e¢\u0006\f\u001a\u0004\b\r\u0010\b\"\u0004\b\u000e\u0010\nR\u0018\u0010\u000f\u001a\u00020\u0007X¦\u000e¢\u0006\f\u001a\u0004\b\u000f\u0010\b\"\u0004\b\u0010\u0010\nR\u0018\u0010\u0011\u001a\u00020\u0007X¦\u000e¢\u0006\f\u001a\u0004\b\u0011\u0010\b\"\u0004\b\u0012\u0010\nR\u0018\u0010\u0013\u001a\u00020\u0007X¦\u000e¢\u0006\f\u001a\u0004\b\u0013\u0010\b\"\u0004\b\u0014\u0010\nR\u0018\u0010\u0015\u001a\u00020\u0007X¦\u000e¢\u0006\f\u001a\u0004\b\u0015\u0010\b\"\u0004\b\u0016\u0010\nR\"\u0010\u0017\u001a\u00020\u00078&@&X§\u000e¢\u0006\u0012\u0012\u0004\b\u0018\u0010\u0019\u001a\u0004\b\u0017\u0010\b\"\u0004\b\u001a\u0010\nR\u0018\u0010\u001b\u001a\u00020\u0007X¦\u000e¢\u0006\f\u001a\u0004\b\u001b\u0010\b\"\u0004\b\u001c\u0010\nø\u0001\u0000\u0082\u0002\u0006\n\u0004\b!0\u0001¨\u0006!À\u0006\u0001"}, d2 = {"Lcom/facebook/react/modules/debug/interfaces/DeveloperSettings;", "", "packagerConnectionSettings", "Lcom/facebook/react/packagerconnection/PackagerConnectionSettings;", "getPackagerConnectionSettings", "()Lcom/facebook/react/packagerconnection/PackagerConnectionSettings;", "isFpsDebugEnabled", "", "()Z", "setFpsDebugEnabled", "(Z)V", "isAnimationFpsDebugEnabled", "setAnimationFpsDebugEnabled", "isJSDevModeEnabled", "setJSDevModeEnabled", "isJSMinifyEnabled", "setJSMinifyEnabled", "isElementInspectorEnabled", "setElementInspectorEnabled", "isDeviceDebugEnabled", "setDeviceDebugEnabled", "isRemoteJSDebugEnabled", "setRemoteJSDebugEnabled", "isStartSamplingProfilerOnInit", "isStartSamplingProfilerOnInit$annotations", "()V", "setStartSamplingProfilerOnInit", "isHotModuleReplacementEnabled", "setHotModuleReplacementEnabled", "addMenuItem", "", "title", "", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public interface DeveloperSettings {
    @Deprecated(message = "Legacy sampling profiler is no longer supported - This field will be removed in React Native 0.77")
    static /* synthetic */ void isStartSamplingProfilerOnInit$annotations() {
    }

    void addMenuItem(String title);

    PackagerConnectionSettings getPackagerConnectionSettings();

    boolean isAnimationFpsDebugEnabled();

    boolean isDeviceDebugEnabled();

    boolean isElementInspectorEnabled();

    boolean isFpsDebugEnabled();

    boolean isHotModuleReplacementEnabled();

    boolean isJSDevModeEnabled();

    boolean isJSMinifyEnabled();

    boolean isRemoteJSDebugEnabled();

    boolean isStartSamplingProfilerOnInit();

    void setAnimationFpsDebugEnabled(boolean z);

    void setDeviceDebugEnabled(boolean z);

    void setElementInspectorEnabled(boolean z);

    void setFpsDebugEnabled(boolean z);

    void setHotModuleReplacementEnabled(boolean z);

    void setJSDevModeEnabled(boolean z);

    void setJSMinifyEnabled(boolean z);

    void setRemoteJSDebugEnabled(boolean z);

    void setStartSamplingProfilerOnInit(boolean z);
}
