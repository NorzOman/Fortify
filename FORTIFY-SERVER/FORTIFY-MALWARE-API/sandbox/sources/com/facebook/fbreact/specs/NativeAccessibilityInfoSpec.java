package com.facebook.fbreact.specs;

import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.turbomodule.core.interfaces.TurboModule;
import javax.annotation.Nonnull;

/* loaded from: classes.dex */
public abstract class NativeAccessibilityInfoSpec extends ReactContextBaseJavaModule implements TurboModule {
    public static final String NAME = "AccessibilityInfo";

    @ReactMethod
    public abstract void announceForAccessibility(String str);

    @ReactMethod
    public void getRecommendedTimeoutMillis(double d, Callback callback) {
    }

    @ReactMethod
    public void isAccessibilityServiceEnabled(Callback callback) {
    }

    @ReactMethod
    public void isGrayscaleEnabled(Callback callback) {
    }

    @ReactMethod
    public void isHighTextContrastEnabled(Callback callback) {
    }

    @ReactMethod
    public void isInvertColorsEnabled(Callback callback) {
    }

    @ReactMethod
    public abstract void isReduceMotionEnabled(Callback callback);

    @ReactMethod
    public abstract void isTouchExplorationEnabled(Callback callback);

    @ReactMethod
    public abstract void setAccessibilityFocus(double d);

    public NativeAccessibilityInfoSpec(ReactApplicationContext reactApplicationContext) {
        super(reactApplicationContext);
    }

    @Override // com.facebook.react.bridge.NativeModule
    @Nonnull
    public String getName() {
        return "AccessibilityInfo";
    }
}
