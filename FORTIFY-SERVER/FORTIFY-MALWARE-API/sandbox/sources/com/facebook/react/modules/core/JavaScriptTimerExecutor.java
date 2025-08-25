package com.facebook.react.modules.core;

import com.facebook.react.bridge.WritableArray;
import kotlin.Metadata;

/* compiled from: JavaScriptTimerExecutor.kt */
@Metadata(d1 = {"\u0000&\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0006\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0000\bf\u0018\u00002\u00020\u0001J\u0010\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u0005H&J\u0010\u0010\u0006\u001a\u00020\u00032\u0006\u0010\u0007\u001a\u00020\bH&J\u0010\u0010\t\u001a\u00020\u00032\u0006\u0010\n\u001a\u00020\u000bH&ø\u0001\u0000\u0082\u0002\u0006\n\u0004\b!0\u0001¨\u0006\fÀ\u0006\u0001"}, d2 = {"Lcom/facebook/react/modules/core/JavaScriptTimerExecutor;", "", "callTimers", "", "timerIDs", "Lcom/facebook/react/bridge/WritableArray;", "callIdleCallbacks", "frameTime", "", "emitTimeDriftWarning", "warningMessage", "", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public interface JavaScriptTimerExecutor {
    void callIdleCallbacks(double frameTime);

    void callTimers(WritableArray timerIDs);

    void emitTimeDriftWarning(String warningMessage);
}
