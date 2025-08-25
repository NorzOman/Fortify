package com.facebook.react.fabric;

import com.facebook.jni.HybridClassBase;
import com.facebook.react.bridge.NativeMap;
import com.facebook.react.fabric.mounting.LayoutMetricsConversions;
import com.facebook.react.interfaces.fabric.SurfaceHandler;

/* loaded from: classes.dex */
public class SurfaceHandlerBinding extends HybridClassBase implements SurfaceHandler {
    public static final int DISPLAY_MODE_HIDDEN = 2;
    public static final int DISPLAY_MODE_SUSPENDED = 1;
    public static final int DISPLAY_MODE_VISIBLE = 0;
    private static final int NO_SURFACE_ID = 0;

    private native void initHybrid(int i, String str);

    private native void setDisplayMode(int i);

    private native void setLayoutConstraintsNative(float f, float f2, float f3, float f4, float f5, float f6, boolean z, boolean z2, float f7);

    @Override // com.facebook.react.interfaces.fabric.SurfaceHandler
    public native String getModuleName();

    @Override // com.facebook.react.interfaces.fabric.SurfaceHandler
    public native int getSurfaceId();

    @Override // com.facebook.react.interfaces.fabric.SurfaceHandler
    public native boolean isRunning();

    @Override // com.facebook.react.interfaces.fabric.SurfaceHandler
    public native void setProps(NativeMap nativeMap);

    static {
        FabricSoLoader.staticInit();
    }

    public SurfaceHandlerBinding(String str) {
        initHybrid(0, str);
    }

    @Override // com.facebook.react.interfaces.fabric.SurfaceHandler
    public void setLayoutConstraints(int i, int i2, int i3, int i4, boolean z, boolean z2, float f) {
        setLayoutConstraintsNative(LayoutMetricsConversions.getMinSize(i) / f, LayoutMetricsConversions.getMaxSize(i) / f, LayoutMetricsConversions.getMinSize(i2) / f, LayoutMetricsConversions.getMaxSize(i2) / f, i3 / f, i4 / f, z, z2, f);
    }

    @Override // com.facebook.react.interfaces.fabric.SurfaceHandler
    public void setMountable(boolean z) {
        setDisplayMode(!z ? 1 : 0);
    }
}
