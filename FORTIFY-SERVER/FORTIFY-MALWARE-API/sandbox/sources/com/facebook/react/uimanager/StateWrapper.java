package com.facebook.react.uimanager;

import com.facebook.react.bridge.ReadableNativeMap;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.common.mapbuffer.ReadableMapBuffer;
import javax.annotation.Nullable;

/* loaded from: classes.dex */
public interface StateWrapper {
    void destroyState();

    @Nullable
    ReadableNativeMap getStateData();

    @Nullable
    ReadableMapBuffer getStateDataMapBuffer();

    void updateState(WritableMap writableMap);
}
