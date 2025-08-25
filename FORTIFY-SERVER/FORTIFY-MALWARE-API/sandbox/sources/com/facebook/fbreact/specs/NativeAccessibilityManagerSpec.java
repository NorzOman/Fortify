package com.facebook.fbreact.specs;

import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.turbomodule.core.interfaces.TurboModule;
import javax.annotation.Nonnull;

/* loaded from: classes.dex */
public abstract class NativeAccessibilityManagerSpec extends ReactContextBaseJavaModule implements TurboModule {
    public static final String NAME = "AccessibilityManager";

    @ReactMethod
    public abstract void announceForAccessibility(String str);

    @ReactMethod
    public void announceForAccessibilityWithOptions(String str, ReadableMap readableMap) {
    }

    @ReactMethod
    public abstract void getCurrentBoldTextState(Callback callback, Callback callback2);

    @ReactMethod
    public void getCurrentDarkerSystemColorsState(Callback callback, Callback callback2) {
    }

    @ReactMethod
    public abstract void getCurrentGrayscaleState(Callback callback, Callback callback2);

    @ReactMethod
    public abstract void getCurrentInvertColorsState(Callback callback, Callback callback2);

    @ReactMethod
    public void getCurrentPrefersCrossFadeTransitionsState(Callback callback, Callback callback2) {
    }

    @ReactMethod
    public abstract void getCurrentReduceMotionState(Callback callback, Callback callback2);

    @ReactMethod
    public abstract void getCurrentReduceTransparencyState(Callback callback, Callback callback2);

    @ReactMethod
    public abstract void getCurrentVoiceOverState(Callback callback, Callback callback2);

    @ReactMethod
    public abstract void setAccessibilityContentSizeMultipliers(ReadableMap readableMap);

    @ReactMethod
    public abstract void setAccessibilityFocus(double d);

    public NativeAccessibilityManagerSpec(ReactApplicationContext reactApplicationContext) {
        super(reactApplicationContext);
    }

    @Override // com.facebook.react.bridge.NativeModule
    @Nonnull
    public String getName() {
        return NAME;
    }
}
