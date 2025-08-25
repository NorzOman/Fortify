package com.facebook.react.devsupport.interfaces;

import com.facebook.react.devsupport.StackTraceHelper;
import com.facebook.react.devsupport.interfaces.DevSupportManager;
import kotlin.Metadata;

/* compiled from: PausedInDebuggerOverlayManager.kt */
@Metadata(d1 = {"\u0000\u001e\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\bf\u0018\u00002\u00020\u0001J\u0018\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u0007H&J\b\u0010\b\u001a\u00020\u0003H&ø\u0001\u0000\u0082\u0002\u0006\n\u0004\b!0\u0001¨\u0006\tÀ\u0006\u0001"}, d2 = {"Lcom/facebook/react/devsupport/interfaces/PausedInDebuggerOverlayManager;", "", "showPausedInDebuggerOverlay", "", StackTraceHelper.MESSAGE_KEY, "", "listener", "Lcom/facebook/react/devsupport/interfaces/DevSupportManager$PausedInDebuggerOverlayCommandListener;", "hidePausedInDebuggerOverlay", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public interface PausedInDebuggerOverlayManager {
    void hidePausedInDebuggerOverlay();

    void showPausedInDebuggerOverlay(String message, DevSupportManager.PausedInDebuggerOverlayCommandListener listener);
}
