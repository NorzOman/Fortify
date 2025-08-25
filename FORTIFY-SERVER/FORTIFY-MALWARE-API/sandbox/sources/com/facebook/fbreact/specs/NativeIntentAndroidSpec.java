package com.facebook.fbreact.specs;

import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.turbomodule.core.interfaces.TurboModule;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/* loaded from: classes.dex */
public abstract class NativeIntentAndroidSpec extends ReactContextBaseJavaModule implements TurboModule {
    public static final String NAME = "IntentAndroid";

    @ReactMethod
    public abstract void canOpenURL(String str, Promise promise);

    @ReactMethod
    public abstract void getInitialURL(Promise promise);

    @ReactMethod
    public abstract void openSettings(Promise promise);

    @ReactMethod
    public abstract void openURL(String str, Promise promise);

    @ReactMethod
    public abstract void sendIntent(String str, @Nullable ReadableArray readableArray, Promise promise);

    public NativeIntentAndroidSpec(ReactApplicationContext reactApplicationContext) {
        super(reactApplicationContext);
    }

    @Override // com.facebook.react.bridge.NativeModule
    @Nonnull
    public String getName() {
        return "IntentAndroid";
    }
}
