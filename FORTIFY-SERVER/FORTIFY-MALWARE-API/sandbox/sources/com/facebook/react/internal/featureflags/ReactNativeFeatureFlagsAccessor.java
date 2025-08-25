package com.facebook.react.internal.featureflags;

import kotlin.Metadata;

/* compiled from: ReactNativeFeatureFlagsAccessor.kt */
@Metadata(d1 = {"\u0000\u0018\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0000\bf\u0018\u00002\u00020\u0001J\u0010\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u0001H&J\b\u0010\u0005\u001a\u00020\u0003H&J\u0012\u0010\u0006\u001a\u0004\u0018\u00010\u00072\u0006\u0010\u0004\u001a\u00020\u0001H&ø\u0001\u0000\u0082\u0002\u0006\n\u0004\b!0\u0001¨\u0006\bÀ\u0006\u0001"}, d2 = {"Lcom/facebook/react/internal/featureflags/ReactNativeFeatureFlagsAccessor;", "Lcom/facebook/react/internal/featureflags/ReactNativeFeatureFlagsProvider;", "override", "", "provider", "dangerouslyReset", "dangerouslyForceOverride", "", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public interface ReactNativeFeatureFlagsAccessor extends ReactNativeFeatureFlagsProvider {
    String dangerouslyForceOverride(ReactNativeFeatureFlagsProvider provider);

    void dangerouslyReset();

    void override(ReactNativeFeatureFlagsProvider provider);
}
