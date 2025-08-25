package com.facebook.react.internal.turbomodule.core.interfaces;

import com.facebook.react.bridge.NativeModule;
import java.util.Collection;
import java.util.List;
import kotlin.Metadata;

/* compiled from: TurboModuleRegistry.kt */
@Metadata(d1 = {"\u00002\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u001e\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010 \n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0000\bf\u0018\u00002\u00020\u0001J\u0012\u0010\u0002\u001a\u0004\u0018\u00010\u00032\u0006\u0010\u0004\u001a\u00020\u0005H&J\u0010\u0010\n\u001a\u00020\u000b2\u0006\u0010\u0004\u001a\u00020\u0005H&J\b\u0010\u0010\u001a\u00020\u0011H&R\u0018\u0010\u0006\u001a\b\u0012\u0004\u0012\u00020\u00030\u0007X¦\u0004¢\u0006\u0006\u001a\u0004\b\b\u0010\tR\u0018\u0010\f\u001a\b\u0012\u0004\u0012\u00020\u00050\rX¦\u0004¢\u0006\u0006\u001a\u0004\b\u000e\u0010\u000fø\u0001\u0000\u0082\u0002\u0006\n\u0004\b!0\u0001¨\u0006\u0012À\u0006\u0001"}, d2 = {"Lcom/facebook/react/internal/turbomodule/core/interfaces/TurboModuleRegistry;", "", "getModule", "Lcom/facebook/react/bridge/NativeModule;", "moduleName", "", "modules", "", "getModules", "()Ljava/util/Collection;", "hasModule", "", "eagerInitModuleNames", "", "getEagerInitModuleNames", "()Ljava/util/List;", "invalidate", "", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public interface TurboModuleRegistry {
    List<String> getEagerInitModuleNames();

    NativeModule getModule(String moduleName);

    Collection<NativeModule> getModules();

    boolean hasModule(String moduleName);

    void invalidate();
}
