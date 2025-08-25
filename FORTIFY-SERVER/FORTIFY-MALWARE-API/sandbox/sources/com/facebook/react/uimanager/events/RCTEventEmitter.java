package com.facebook.react.uimanager.events;

import com.facebook.react.bridge.JavaScriptModule;
import com.facebook.react.bridge.WritableArray;
import com.facebook.react.bridge.WritableMap;
import kotlin.Deprecated;
import kotlin.Metadata;

/* compiled from: RCTEventEmitter.kt */
@Deprecated(message = "Use [RCTModernEventEmitter] instead")
@Metadata(d1 = {"\u0000,\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\bg\u0018\u00002\u00020\u0001J\"\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u00072\b\u0010\b\u001a\u0004\u0018\u00010\tH'J \u0010\n\u001a\u00020\u00032\u0006\u0010\u0006\u001a\u00020\u00072\u0006\u0010\u000b\u001a\u00020\f2\u0006\u0010\r\u001a\u00020\fH'ø\u0001\u0000\u0082\u0002\u0006\n\u0004\b!0\u0001¨\u0006\u000eÀ\u0006\u0001"}, d2 = {"Lcom/facebook/react/uimanager/events/RCTEventEmitter;", "Lcom/facebook/react/bridge/JavaScriptModule;", "receiveEvent", "", "targetTag", "", "eventName", "", "params", "Lcom/facebook/react/bridge/WritableMap;", "receiveTouches", "touches", "Lcom/facebook/react/bridge/WritableArray;", "changedIndices", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public interface RCTEventEmitter extends JavaScriptModule {
    @Deprecated(message = "Use [RCTModernEventEmitter.receiveEvent] instead")
    void receiveEvent(int targetTag, String eventName, WritableMap params);

    @Deprecated(message = "Dispatch the TouchEvent using [EventDispatcher] instead")
    void receiveTouches(String eventName, WritableArray touches, WritableArray changedIndices);
}
