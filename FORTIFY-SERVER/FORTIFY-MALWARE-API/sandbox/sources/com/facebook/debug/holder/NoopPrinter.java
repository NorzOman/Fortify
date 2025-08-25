package com.facebook.debug.holder;

import com.facebook.debug.debugoverlay.model.DebugOverlayTag;
import com.facebook.react.devsupport.StackTraceHelper;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: NoopPrinter.kt */
@Metadata(d1 = {"\u00000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0011\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0000\bÀ\u0002\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003J5\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u00072\u0006\u0010\b\u001a\u00020\t2\u0016\u0010\n\u001a\f\u0012\b\b\u0001\u0012\u0004\u0018\u00010\f0\u000b\"\u0004\u0018\u00010\fH\u0016¢\u0006\u0002\u0010\rJ\u0018\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u00072\u0006\u0010\b\u001a\u00020\tH\u0016J\u0010\u0010\u000e\u001a\u00020\u000f2\u0006\u0010\u0006\u001a\u00020\u0007H\u0016¨\u0006\u0010"}, d2 = {"Lcom/facebook/debug/holder/NoopPrinter;", "Lcom/facebook/debug/holder/Printer;", "<init>", "()V", "logMessage", "", "tag", "Lcom/facebook/debug/debugoverlay/model/DebugOverlayTag;", StackTraceHelper.MESSAGE_KEY, "", "args", "", "", "(Lcom/facebook/debug/debugoverlay/model/DebugOverlayTag;Ljava/lang/String;[Ljava/lang/Object;)V", "shouldDisplayLogMessage", "", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class NoopPrinter implements Printer {
    public static final NoopPrinter INSTANCE = new NoopPrinter();

    @Override // com.facebook.debug.holder.Printer
    public void logMessage(DebugOverlayTag tag, String message) {
        Intrinsics.checkNotNullParameter(tag, "tag");
        Intrinsics.checkNotNullParameter(message, "message");
    }

    @Override // com.facebook.debug.holder.Printer
    public void logMessage(DebugOverlayTag tag, String message, Object... args) {
        Intrinsics.checkNotNullParameter(tag, "tag");
        Intrinsics.checkNotNullParameter(message, "message");
        Intrinsics.checkNotNullParameter(args, "args");
    }

    @Override // com.facebook.debug.holder.Printer
    public boolean shouldDisplayLogMessage(DebugOverlayTag tag) {
        Intrinsics.checkNotNullParameter(tag, "tag");
        return false;
    }

    private NoopPrinter() {
    }
}
