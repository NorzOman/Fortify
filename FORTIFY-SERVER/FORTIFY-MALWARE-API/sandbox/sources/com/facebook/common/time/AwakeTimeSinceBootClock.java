package com.facebook.common.time;

/* loaded from: classes.dex */
public class AwakeTimeSinceBootClock implements MonotonicNanoClock {
    private static final AwakeTimeSinceBootClock INSTANCE = new AwakeTimeSinceBootClock();

    private AwakeTimeSinceBootClock() {
    }

    public static AwakeTimeSinceBootClock get() {
        return INSTANCE;
    }

    @Override // com.facebook.common.time.MonotonicClock
    public long nowNanos() {
        return System.nanoTime();
    }
}
