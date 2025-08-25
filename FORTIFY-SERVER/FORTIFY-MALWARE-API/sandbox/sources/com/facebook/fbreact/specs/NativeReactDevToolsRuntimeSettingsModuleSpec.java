package com.facebook.fbreact.specs;

import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.turbomodule.core.interfaces.TurboModule;
import javax.annotation.Nonnull;

/* loaded from: classes.dex */
public abstract class NativeReactDevToolsRuntimeSettingsModuleSpec extends ReactContextBaseJavaModule implements TurboModule {
    public static final String NAME = "ReactDevToolsRuntimeSettingsModule";

    @ReactMethod(isBlockingSynchronousMethod = true)
    public abstract WritableMap getReloadAndProfileConfig();

    @ReactMethod
    public abstract void setReloadAndProfileConfig(ReadableMap readableMap);

    public NativeReactDevToolsRuntimeSettingsModuleSpec(ReactApplicationContext reactApplicationContext) {
        super(reactApplicationContext);
    }

    @Override // com.facebook.react.bridge.NativeModule
    @Nonnull
    public String getName() {
        return "ReactDevToolsRuntimeSettingsModule";
    }
}
