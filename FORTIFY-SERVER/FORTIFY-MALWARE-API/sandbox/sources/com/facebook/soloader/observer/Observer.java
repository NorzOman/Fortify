package com.facebook.soloader.observer;

import com.facebook.soloader.SoFileLoader;
import com.facebook.soloader.SoSource;
import com.facebook.soloader.recovery.RecoveryStrategy;
import javax.annotation.Nullable;

/* loaded from: classes.dex */
public interface Observer {
    void onGetDependenciesEnd(@Nullable Throwable th);

    void onGetDependenciesStart();

    void onLoadDependencyEnd(@Nullable Throwable th, boolean z);

    void onLoadDependencyStart(String str, int i);

    void onLoadLibraryEnd(@Nullable Throwable th, boolean z);

    void onLoadLibraryStart(String str, @Nullable String str2, int i);

    void onRecoveryEnd(@Nullable Throwable th);

    void onRecoveryStart(RecoveryStrategy recoveryStrategy);

    void onSoFileLoaderLoadEnd(@Nullable Throwable th);

    void onSoFileLoaderLoadStart(SoFileLoader soFileLoader, String str, int i);

    void onSoSourceLoadLibraryEnd(@Nullable Throwable th);

    void onSoSourceLoadLibraryStart(SoSource soSource);
}
