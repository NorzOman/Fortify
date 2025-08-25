package com.facebook.react.fabric;

import com.facebook.common.logging.FLog;
import com.facebook.jni.HybridClassBase;
import com.facebook.react.bridge.NativeMap;
import com.facebook.react.bridge.ReadableNativeMap;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.common.mapbuffer.ReadableMapBuffer;
import com.facebook.react.uimanager.StateWrapper;

/* loaded from: classes.dex */
public class StateWrapperImpl extends HybridClassBase implements StateWrapper {
    private static final String TAG = "StateWrapperImpl";

    private native ReadableNativeMap getStateDataImpl();

    private native ReadableMapBuffer getStateMapBufferDataImpl();

    private native void initHybrid();

    public native void updateStateImpl(NativeMap nativeMap);

    static {
        FabricSoLoader.staticInit();
    }

    private StateWrapperImpl() {
        initHybrid();
    }

    @Override // com.facebook.react.uimanager.StateWrapper
    public ReadableMapBuffer getStateDataMapBuffer() {
        if (!isValid()) {
            FLog.e(TAG, "Race between StateWrapperImpl destruction and getState");
            return null;
        }
        return getStateMapBufferDataImpl();
    }

    @Override // com.facebook.react.uimanager.StateWrapper
    public ReadableNativeMap getStateData() {
        if (!isValid()) {
            FLog.e(TAG, "Race between StateWrapperImpl destruction and getState");
            return null;
        }
        return getStateDataImpl();
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.facebook.react.uimanager.StateWrapper
    public void updateState(WritableMap writableMap) {
        if (!isValid()) {
            FLog.e(TAG, "Race between StateWrapperImpl destruction and updateState");
        } else {
            updateStateImpl((NativeMap) writableMap);
        }
    }

    @Override // com.facebook.react.uimanager.StateWrapper
    public void destroyState() {
        if (isValid()) {
            resetNative();
        }
    }

    public String toString() {
        if (!isValid()) {
            return "<destroyed>";
        }
        ReadableMapBuffer stateMapBufferDataImpl = getStateMapBufferDataImpl();
        if (stateMapBufferDataImpl != null) {
            return stateMapBufferDataImpl.toString();
        }
        ReadableNativeMap stateDataImpl = getStateDataImpl();
        if (stateDataImpl == null) {
            return "<unexpected null>";
        }
        return stateDataImpl.toString();
    }
}
