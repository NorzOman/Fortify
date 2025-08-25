package com.facebook.react.uimanager.events;

import androidx.core.app.NotificationCompat;
import com.facebook.react.bridge.WritableMap;
import kotlin.Deprecated;
import kotlin.Metadata;

/* compiled from: RCTModernEventEmitter.kt */
@Metadata(d1 = {"\u00002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0000\bf\u0018\u00002\u00020\u0001J*\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u00052\u0006\u0010\u0007\u001a\u00020\b2\b\u0010\t\u001a\u0004\u0018\u00010\nH&JB\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u00052\u0006\u0010\u0007\u001a\u00020\b2\u0006\u0010\u000b\u001a\u00020\f2\u0006\u0010\r\u001a\u00020\u00052\b\u0010\t\u001a\u0004\u0018\u00010\n2\u0006\u0010\u000e\u001a\u00020\u0005H&J\u0010\u0010\u000f\u001a\u00020\u00032\u0006\u0010\u0010\u001a\u00020\u0011H'ø\u0001\u0000\u0082\u0002\u0006\n\u0004\b!0\u0001¨\u0006\u0012À\u0006\u0001"}, d2 = {"Lcom/facebook/react/uimanager/events/RCTModernEventEmitter;", "Lcom/facebook/react/uimanager/events/RCTEventEmitter;", "receiveEvent", "", "surfaceId", "", "targetTag", "eventName", "", "params", "Lcom/facebook/react/bridge/WritableMap;", "canCoalesceEvent", "", "customCoalesceKey", "category", "receiveTouches", NotificationCompat.CATEGORY_EVENT, "Lcom/facebook/react/uimanager/events/TouchEvent;", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public interface RCTModernEventEmitter extends RCTEventEmitter {
    void receiveEvent(int surfaceId, int targetTag, String eventName, WritableMap params);

    void receiveEvent(int surfaceId, int targetTag, String eventName, boolean canCoalesceEvent, int customCoalesceKey, WritableMap params, int category);

    @Deprecated(message = "Dispatch the TouchEvent using [EventDispatcher] instead")
    void receiveTouches(TouchEvent event);
}
