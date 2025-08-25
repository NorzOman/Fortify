package com.facebook.debug.holder;

import com.facebook.debug.debugoverlay.model.DebugOverlayTag;
import com.facebook.react.devsupport.StackTraceHelper;
import kotlin.Metadata;

/* compiled from: Printer.kt */
@Metadata(d1 = {"\u0000*\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0011\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0000\b`\u0018\u00002\u00020\u0001J5\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u00072\u0016\u0010\b\u001a\f\u0012\b\b\u0001\u0012\u0004\u0018\u00010\u00010\t\"\u0004\u0018\u00010\u0001H&¢\u0006\u0002\u0010\nJ\u0018\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u0007H&J\u0010\u0010\u000b\u001a\u00020\f2\u0006\u0010\u0004\u001a\u00020\u0005H&ø\u0001\u0000\u0082\u0002\u0006\n\u0004\b!0\u0001¨\u0006\rÀ\u0006\u0001"}, d2 = {"Lcom/facebook/debug/holder/Printer;", "", "logMessage", "", "tag", "Lcom/facebook/debug/debugoverlay/model/DebugOverlayTag;", StackTraceHelper.MESSAGE_KEY, "", "args", "", "(Lcom/facebook/debug/debugoverlay/model/DebugOverlayTag;Ljava/lang/String;[Ljava/lang/Object;)V", "shouldDisplayLogMessage", "", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public interface Printer {
    void logMessage(DebugOverlayTag tag, String message);

    void logMessage(DebugOverlayTag tag, String message, Object... args);

    boolean shouldDisplayLogMessage(DebugOverlayTag tag);
}
