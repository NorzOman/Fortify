package com.oblador.vectoricons;

import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.turbomodule.core.interfaces.TurboModule;
import javax.annotation.Nonnull;

/* loaded from: classes.dex */
public abstract class NativeRNVectorIconsSpec extends ReactContextBaseJavaModule implements TurboModule {
    public static final String NAME = "RNVectorIcons";

    @ReactMethod
    public abstract void getImageForFont(String str, String str2, double d, double d2, Promise promise);

    @ReactMethod(isBlockingSynchronousMethod = true)
    public abstract String getImageForFontSync(String str, String str2, double d, double d2);

    @ReactMethod
    public abstract void loadFontWithFileName(String str, String str2, Promise promise);

    public NativeRNVectorIconsSpec(ReactApplicationContext reactApplicationContext) {
        super(reactApplicationContext);
    }

    @Override // com.facebook.react.bridge.NativeModule
    @Nonnull
    public String getName() {
        return "RNVectorIcons";
    }
}
