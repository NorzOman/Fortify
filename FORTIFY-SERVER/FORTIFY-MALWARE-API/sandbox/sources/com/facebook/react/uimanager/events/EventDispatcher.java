package com.facebook.react.uimanager.events;

import androidx.core.app.NotificationCompat;
import kotlin.Deprecated;
import kotlin.Metadata;

/* compiled from: EventDispatcher.kt */
@Metadata(d1 = {"\u0000:\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\b\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\bf\u0018\u00002\u00020\u0001J\u0014\u0010\u0002\u001a\u00020\u00032\n\u0010\u0004\u001a\u0006\u0012\u0002\b\u00030\u0005H&J\b\u0010\u0006\u001a\u00020\u0003H&J\u0010\u0010\u0007\u001a\u00020\u00032\u0006\u0010\b\u001a\u00020\tH&J\u0010\u0010\n\u001a\u00020\u00032\u0006\u0010\b\u001a\u00020\tH&J\u0010\u0010\u000b\u001a\u00020\u00032\u0006\u0010\b\u001a\u00020\fH&J\u0010\u0010\r\u001a\u00020\u00032\u0006\u0010\b\u001a\u00020\fH&J\u0018\u0010\u000e\u001a\u00020\u00032\u0006\u0010\u000f\u001a\u00020\u00102\u0006\u0010\u0011\u001a\u00020\u0012H'J\u0018\u0010\u000e\u001a\u00020\u00032\u0006\u0010\u000f\u001a\u00020\u00102\u0006\u0010\u0011\u001a\u00020\u0013H&J\u0010\u0010\u0014\u001a\u00020\u00032\u0006\u0010\u000f\u001a\u00020\u0010H&J\b\u0010\u0015\u001a\u00020\u0003H&ø\u0001\u0000\u0082\u0002\u0006\n\u0004\b!0\u0001¨\u0006\u0016À\u0006\u0001"}, d2 = {"Lcom/facebook/react/uimanager/events/EventDispatcher;", "", "dispatchEvent", "", NotificationCompat.CATEGORY_EVENT, "Lcom/facebook/react/uimanager/events/Event;", "dispatchAllEvents", "addListener", "listener", "Lcom/facebook/react/uimanager/events/EventDispatcherListener;", "removeListener", "addBatchEventDispatchedListener", "Lcom/facebook/react/uimanager/events/BatchEventDispatchedListener;", "removeBatchEventDispatchedListener", "registerEventEmitter", "uiManagerType", "", "eventEmitter", "Lcom/facebook/react/uimanager/events/RCTEventEmitter;", "Lcom/facebook/react/uimanager/events/RCTModernEventEmitter;", "unregisterEventEmitter", "onCatalystInstanceDestroyed", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public interface EventDispatcher {
    void addBatchEventDispatchedListener(BatchEventDispatchedListener listener);

    void addListener(EventDispatcherListener listener);

    void dispatchAllEvents();

    void dispatchEvent(Event<?> event);

    void onCatalystInstanceDestroyed();

    @Deprecated(message = "Use the modern version with RCTModernEventEmitter")
    void registerEventEmitter(int uiManagerType, RCTEventEmitter eventEmitter);

    void registerEventEmitter(int uiManagerType, RCTModernEventEmitter eventEmitter);

    void removeBatchEventDispatchedListener(BatchEventDispatchedListener listener);

    void removeListener(EventDispatcherListener listener);

    void unregisterEventEmitter(int uiManagerType);
}
