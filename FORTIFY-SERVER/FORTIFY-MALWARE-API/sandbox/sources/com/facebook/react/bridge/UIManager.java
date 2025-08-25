package com.facebook.react.bridge;

import android.view.View;
import androidx.core.app.NotificationCompat;
import com.facebook.react.uimanager.events.EventDispatcher;
import kotlin.Deprecated;
import kotlin.Metadata;
import kotlin.ReplaceWith;

/* compiled from: UIManager.kt */
@Metadata(d1 = {"\u0000N\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0002\b\u0004\n\u0002\u0010\u0002\n\u0002\b\t\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u000b\bf\u0018\u00002\u00020\u0001J+\u0010\u0002\u001a\u00020\u0003\"\n\b\u0000\u0010\u0004*\u0004\u0018\u00010\u00052\u0006\u0010\u0006\u001a\u0002H\u00042\b\u0010\u0007\u001a\u0004\u0018\u00010\bH'¢\u0006\u0002\u0010\tJC\u0010\n\u001a\u00020\u0003\"\n\b\u0000\u0010\u0004*\u0004\u0018\u00010\u00052\u0006\u0010\u0006\u001a\u0002H\u00042\u0006\u0010\u000b\u001a\u00020\f2\b\u0010\u0007\u001a\u0004\u0018\u00010\b2\u0006\u0010\r\u001a\u00020\u00032\u0006\u0010\u000e\u001a\u00020\u0003H'¢\u0006\u0002\u0010\u000fJ\u0010\u0010\u0010\u001a\u00020\u00112\u0006\u0010\u0012\u001a\u00020\u0003H'J0\u0010\u0013\u001a\u00020\u00112\u0006\u0010\u0014\u001a\u00020\u00032\u0006\u0010\r\u001a\u00020\u00032\u0006\u0010\u000e\u001a\u00020\u00032\u0006\u0010\u0015\u001a\u00020\u00032\u0006\u0010\u0016\u001a\u00020\u0003H'J\"\u0010\u0017\u001a\u00020\u00112\u0006\u0010\u0018\u001a\u00020\u00032\u0006\u0010\u0019\u001a\u00020\u00032\b\u0010\u001a\u001a\u0004\u0018\u00010\u001bH&J\"\u0010\u0017\u001a\u00020\u00112\u0006\u0010\u0018\u001a\u00020\u00032\u0006\u0010\u0019\u001a\u00020\f2\b\u0010\u001a\u001a\u0004\u0018\u00010\u001bH&J\u001a\u0010 \u001a\u00020\u00112\u0006\u0010\u0018\u001a\u00020\u00032\b\u0010!\u001a\u0004\u0018\u00010\"H'J\u0018\u0010#\u001a\u00020\u00112\u0006\u0010\u0018\u001a\u00020\u00032\u0006\u0010$\u001a\u00020\u0003H&J\u0012\u0010%\u001a\u00020\u00112\b\u0010&\u001a\u0004\u0018\u00010'H&J\u0012\u0010(\u001a\u00020\u00112\b\u0010&\u001a\u0004\u0018\u00010'H&J\u0012\u0010)\u001a\u0004\u0018\u00010\u00052\u0006\u0010\u0018\u001a\u00020\u0003H&J\"\u0010*\u001a\u00020\u00112\u0006\u0010\u0018\u001a\u00020\u00032\u0006\u0010+\u001a\u00020\f2\b\u0010,\u001a\u0004\u0018\u00010\bH'J*\u0010*\u001a\u00020\u00112\u0006\u0010\u0012\u001a\u00020\u00032\u0006\u0010\u0018\u001a\u00020\u00032\u0006\u0010+\u001a\u00020\f2\b\u0010,\u001a\u0004\u0018\u00010\bH&J\u0012\u0010-\u001a\u0004\u0018\u00010\f2\u0006\u0010+\u001a\u00020\fH'J\b\u0010.\u001a\u00020\u0011H&J\b\u0010/\u001a\u00020\u0011H&J\u0018\u00100\u001a\u00020\u00112\u0006\u0010\u0012\u001a\u00020\u00032\u0006\u0010\u0018\u001a\u00020\u0003H&J\u0018\u00101\u001a\u00020\u00112\u0006\u0010\u0012\u001a\u00020\u00032\u0006\u0010\u0018\u001a\u00020\u0003H&R\u0012\u0010\u001c\u001a\u00020\u001dX¦\u0004¢\u0006\u0006\u001a\u0004\b\u001e\u0010\u001fø\u0001\u0000\u0082\u0002\u0006\n\u0004\b!0\u0001¨\u00062À\u0006\u0001"}, d2 = {"Lcom/facebook/react/bridge/UIManager;", "Lcom/facebook/react/bridge/PerformanceCounter;", "addRootView", "", "T", "Landroid/view/View;", "rootView", "initialProps", "Lcom/facebook/react/bridge/WritableMap;", "(Landroid/view/View;Lcom/facebook/react/bridge/WritableMap;)I", "startSurface", "moduleName", "", "widthMeasureSpec", "heightMeasureSpec", "(Landroid/view/View;Ljava/lang/String;Lcom/facebook/react/bridge/WritableMap;II)I", "stopSurface", "", "surfaceId", "updateRootLayoutSpecs", "rootTag", "offsetX", "offsetY", "dispatchCommand", "reactTag", "commandId", "commandArgs", "Lcom/facebook/react/bridge/ReadableArray;", "eventDispatcher", "Lcom/facebook/react/uimanager/events/EventDispatcher;", "getEventDispatcher", "()Lcom/facebook/react/uimanager/events/EventDispatcher;", "synchronouslyUpdateViewOnUIThread", "props", "Lcom/facebook/react/bridge/ReadableMap;", "sendAccessibilityEvent", "eventType", "addUIManagerEventListener", "listener", "Lcom/facebook/react/bridge/UIManagerListener;", "removeUIManagerEventListener", "resolveView", "receiveEvent", "eventName", NotificationCompat.CATEGORY_EVENT, "resolveCustomDirectEventName", "initialize", "invalidate", "markActiveTouchForTag", "sweepActiveTouchForTag", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public interface UIManager extends PerformanceCounter {
    @Deprecated(message = "")
    <T extends View> int addRootView(T rootView, WritableMap initialProps);

    void addUIManagerEventListener(UIManagerListener listener);

    void dispatchCommand(int reactTag, int commandId, ReadableArray commandArgs);

    void dispatchCommand(int reactTag, String commandId, ReadableArray commandArgs);

    EventDispatcher getEventDispatcher();

    void initialize();

    void invalidate();

    void markActiveTouchForTag(int surfaceId, int reactTag);

    void receiveEvent(int surfaceId, int reactTag, String eventName, WritableMap event);

    @Deprecated(message = "", replaceWith = @ReplaceWith(expression = "receiveEvent(surfaceId, reactTag, eventName, event)", imports = {}))
    void receiveEvent(int reactTag, String eventName, WritableMap event);

    void removeUIManagerEventListener(UIManagerListener listener);

    @Deprecated(message = "")
    String resolveCustomDirectEventName(String eventName);

    View resolveView(int reactTag);

    void sendAccessibilityEvent(int reactTag, int eventType);

    <T extends View> int startSurface(T rootView, String moduleName, WritableMap initialProps, int widthMeasureSpec, int heightMeasureSpec);

    void stopSurface(int surfaceId);

    void sweepActiveTouchForTag(int surfaceId, int reactTag);

    void synchronouslyUpdateViewOnUIThread(int reactTag, ReadableMap props);

    void updateRootLayoutSpecs(int rootTag, int widthMeasureSpec, int heightMeasureSpec, int offsetX, int offsetY);
}
