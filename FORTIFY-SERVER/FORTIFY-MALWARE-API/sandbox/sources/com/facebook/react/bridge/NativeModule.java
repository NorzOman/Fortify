package com.facebook.react.bridge;

import javax.annotation.Nonnull;

/* loaded from: classes.dex */
public interface NativeModule {
    default boolean canOverrideExistingModule() {
        return false;
    }

    @Nonnull
    String getName();

    void initialize();

    void invalidate();

    @Deprecated(forRemoval = true, since = "Use invalidate method instead")
    default void onCatalystInstanceDestroy() {
    }
}
