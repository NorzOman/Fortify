package com.facebook.react.uimanager.events;

import com.facebook.react.bridge.WritableMap;
import kotlin.Deprecated;
import kotlin.Metadata;

/* compiled from: SynchronousEventReceiver.kt */
@Deprecated(message = "Experimental")
@Metadata(d1 = {"\u0000,\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\bg\u0018\u00002\u00020\u0001JB\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u00052\u0006\u0010\u0007\u001a\u00020\b2\u0006\u0010\t\u001a\u00020\n2\b\u0010\u000b\u001a\u0004\u0018\u00010\f2\u0006\u0010\r\u001a\u00020\u00052\u0006\u0010\u000e\u001a\u00020\nH&ø\u0001\u0000\u0082\u0002\u0006\n\u0004\b!0\u0001¨\u0006\u000fÀ\u0006\u0001"}, d2 = {"Lcom/facebook/react/uimanager/events/SynchronousEventReceiver;", "", "receiveEvent", "", "surfaceId", "", "reactTag", "eventName", "", "canCoalesceEvent", "", "params", "Lcom/facebook/react/bridge/WritableMap;", "eventCategory", "experimental_isSynchronous", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public interface SynchronousEventReceiver {
    void receiveEvent(int surfaceId, int reactTag, String eventName, boolean canCoalesceEvent, WritableMap params, int eventCategory, boolean experimental_isSynchronous);
}
