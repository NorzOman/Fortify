package com.facebook.react.bridge;

import android.app.Activity;

/* loaded from: classes.dex */
public abstract class ReactContextBaseJavaModule extends BaseJavaModule {
    public ReactContextBaseJavaModule() {
        super(null);
    }

    public ReactContextBaseJavaModule(ReactApplicationContext reactApplicationContext) {
        super(reactApplicationContext);
    }

    protected final Activity getCurrentActivity() {
        return getReactApplicationContext().getCurrentActivity();
    }
}
