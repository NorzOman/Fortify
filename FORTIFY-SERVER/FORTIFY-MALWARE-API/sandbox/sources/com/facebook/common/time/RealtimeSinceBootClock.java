package com.facebook.common.time;

import java.util.concurrent.TimeUnit;

/* loaded from: classes.dex */
public class RealtimeSinceBootClock implements MonotonicClock {
    private static final RealtimeSinceBootClock INSTANCE = new RealtimeSinceBootClock();

    private RealtimeSinceBootClock() {
    }

    public static RealtimeSinceBootClock get() {
        return INSTANCE;
    }

    @Override // com.facebook.common.time.MonotonicClock
    public long now() {
        return android.os.SystemClock.elapsedRealtime();
    }

    @Override // com.facebook.common.time.MonotonicClock
    public long nowNanos() {
        return TimeUnit.MILLISECONDS.toNanos(now());
    }
}
