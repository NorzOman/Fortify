package com.facebook.react.uimanager.events;

import androidx.core.app.NotificationCompat;
import com.facebook.common.logging.FLog;
import kotlin.Deprecated;
import kotlin.Metadata;
import kotlin.jvm.JvmStatic;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: BlackHoleEventDispatcher.kt */
@Metadata(d1 = {"\u0000<\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\b\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\u0018\u0000 \u00182\u00020\u0001:\u0001\u0018B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003J\u0014\u0010\u0004\u001a\u00020\u00052\n\u0010\u0006\u001a\u0006\u0012\u0002\b\u00030\u0007H\u0016J\b\u0010\b\u001a\u00020\u0005H\u0016J\u0010\u0010\t\u001a\u00020\u00052\u0006\u0010\n\u001a\u00020\u000bH\u0016J\u0010\u0010\f\u001a\u00020\u00052\u0006\u0010\n\u001a\u00020\u000bH\u0016J\u0010\u0010\r\u001a\u00020\u00052\u0006\u0010\n\u001a\u00020\u000eH\u0016J\u0010\u0010\u000f\u001a\u00020\u00052\u0006\u0010\n\u001a\u00020\u000eH\u0016J\u0018\u0010\u0010\u001a\u00020\u00052\u0006\u0010\u0011\u001a\u00020\u00122\u0006\u0010\u0013\u001a\u00020\u0014H\u0017J\u0018\u0010\u0010\u001a\u00020\u00052\u0006\u0010\u0011\u001a\u00020\u00122\u0006\u0010\u0013\u001a\u00020\u0015H\u0016J\u0010\u0010\u0016\u001a\u00020\u00052\u0006\u0010\u0011\u001a\u00020\u0012H\u0016J\b\u0010\u0017\u001a\u00020\u0005H\u0016¨\u0006\u0019"}, d2 = {"Lcom/facebook/react/uimanager/events/BlackHoleEventDispatcher;", "Lcom/facebook/react/uimanager/events/EventDispatcher;", "<init>", "()V", "dispatchEvent", "", NotificationCompat.CATEGORY_EVENT, "Lcom/facebook/react/uimanager/events/Event;", "dispatchAllEvents", "addListener", "listener", "Lcom/facebook/react/uimanager/events/EventDispatcherListener;", "removeListener", "addBatchEventDispatchedListener", "Lcom/facebook/react/uimanager/events/BatchEventDispatchedListener;", "removeBatchEventDispatchedListener", "registerEventEmitter", "uiManagerType", "", "eventEmitter", "Lcom/facebook/react/uimanager/events/RCTEventEmitter;", "Lcom/facebook/react/uimanager/events/RCTModernEventEmitter;", "unregisterEventEmitter", "onCatalystInstanceDestroyed", "Companion", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class BlackHoleEventDispatcher implements EventDispatcher {

    /* renamed from: Companion, reason: from kotlin metadata */
    public static final Companion INSTANCE = new Companion(null);
    private static final EventDispatcher eventDispatcher = new BlackHoleEventDispatcher();

    @JvmStatic
    public static final EventDispatcher get() {
        return INSTANCE.get();
    }

    @Override // com.facebook.react.uimanager.events.EventDispatcher
    public void addBatchEventDispatchedListener(BatchEventDispatchedListener listener) {
        Intrinsics.checkNotNullParameter(listener, "listener");
    }

    @Override // com.facebook.react.uimanager.events.EventDispatcher
    public void addListener(EventDispatcherListener listener) {
        Intrinsics.checkNotNullParameter(listener, "listener");
    }

    @Override // com.facebook.react.uimanager.events.EventDispatcher
    public void dispatchAllEvents() {
    }

    @Override // com.facebook.react.uimanager.events.EventDispatcher
    public void onCatalystInstanceDestroyed() {
    }

    @Override // com.facebook.react.uimanager.events.EventDispatcher
    @Deprecated(message = "Deprecated in Java")
    public void registerEventEmitter(int uiManagerType, RCTEventEmitter eventEmitter) {
        Intrinsics.checkNotNullParameter(eventEmitter, "eventEmitter");
    }

    @Override // com.facebook.react.uimanager.events.EventDispatcher
    public void registerEventEmitter(int uiManagerType, RCTModernEventEmitter eventEmitter) {
        Intrinsics.checkNotNullParameter(eventEmitter, "eventEmitter");
    }

    @Override // com.facebook.react.uimanager.events.EventDispatcher
    public void removeBatchEventDispatchedListener(BatchEventDispatchedListener listener) {
        Intrinsics.checkNotNullParameter(listener, "listener");
    }

    @Override // com.facebook.react.uimanager.events.EventDispatcher
    public void removeListener(EventDispatcherListener listener) {
        Intrinsics.checkNotNullParameter(listener, "listener");
    }

    @Override // com.facebook.react.uimanager.events.EventDispatcher
    public void unregisterEventEmitter(int uiManagerType) {
    }

    private BlackHoleEventDispatcher() {
    }

    @Override // com.facebook.react.uimanager.events.EventDispatcher
    public void dispatchEvent(Event<?> event) {
        Intrinsics.checkNotNullParameter(event, "event");
        FLog.d("BlackHoleEventDispatcher", "Trying to emit event to JS, but the React instance isn't ready. Event: " + event.getEventName());
    }

    /* compiled from: BlackHoleEventDispatcher.kt */
    @Metadata(d1 = {"\u0000\u0014\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0002\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003J\b\u0010\u0006\u001a\u00020\u0005H\u0007R\u000e\u0010\u0004\u001a\u00020\u0005X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\u0007"}, d2 = {"Lcom/facebook/react/uimanager/events/BlackHoleEventDispatcher$Companion;", "", "<init>", "()V", "eventDispatcher", "Lcom/facebook/react/uimanager/events/EventDispatcher;", "get", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }

        @JvmStatic
        public final EventDispatcher get() {
            return BlackHoleEventDispatcher.eventDispatcher;
        }
    }
}
