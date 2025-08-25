package com.facebook.react.runtime.internal.bolts;

import com.facebook.react.bridge.UiThreadUtil;
import java.util.concurrent.Executor;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: Executors.kt */
@Metadata(d1 = {"\u0000\u0014\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0004\bÀ\u0002\u0018\u00002\u00020\u0001:\u0002\u0007\bB\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003R\u0010\u0010\u0004\u001a\u00020\u00058\u0006X\u0087\u0004¢\u0006\u0002\n\u0000R\u0010\u0010\u0006\u001a\u00020\u00058\u0006X\u0087\u0004¢\u0006\u0002\n\u0000¨\u0006\t"}, d2 = {"Lcom/facebook/react/runtime/internal/bolts/Executors;", "", "<init>", "()V", "UI_THREAD", "Ljava/util/concurrent/Executor;", "IMMEDIATE", "UIThreadExecutor", "ImmediateExecutor", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class Executors {
    public static final Executors INSTANCE = new Executors();
    public static final Executor UI_THREAD = new UIThreadExecutor();
    public static final Executor IMMEDIATE = new ImmediateExecutor();

    private Executors() {
    }

    /* compiled from: Executors.kt */
    @Metadata(d1 = {"\u0000\u0018\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\b\u0002\u0018\u00002\u00020\u0001B\u0007¢\u0006\u0004\b\u0002\u0010\u0003J\u0010\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u0007H\u0016¨\u0006\b"}, d2 = {"Lcom/facebook/react/runtime/internal/bolts/Executors$UIThreadExecutor;", "Ljava/util/concurrent/Executor;", "<init>", "()V", "execute", "", "command", "Ljava/lang/Runnable;", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
    private static final class UIThreadExecutor implements Executor {
        @Override // java.util.concurrent.Executor
        public void execute(Runnable command) {
            Intrinsics.checkNotNullParameter(command, "command");
            UiThreadUtil.runOnUiThread(command);
        }
    }

    /* compiled from: Executors.kt */
    @Metadata(d1 = {"\u0000\u0018\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\b\u0002\u0018\u00002\u00020\u0001B\u0007¢\u0006\u0004\b\u0002\u0010\u0003J\u0010\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u0007H\u0016¨\u0006\b"}, d2 = {"Lcom/facebook/react/runtime/internal/bolts/Executors$ImmediateExecutor;", "Ljava/util/concurrent/Executor;", "<init>", "()V", "execute", "", "command", "Ljava/lang/Runnable;", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
    private static final class ImmediateExecutor implements Executor {
        @Override // java.util.concurrent.Executor
        public void execute(Runnable command) {
            Intrinsics.checkNotNullParameter(command, "command");
            command.run();
        }
    }
}
