package com.facebook.common.time;

import java.util.concurrent.TimeUnit;

/* loaded from: classes.dex */
public interface MonotonicClock {
    long nowNanos();

    default long now() {
        return TimeUnit.NANOSECONDS.toMillis(nowNanos());
    }

    static MonotonicClock of(Clock clock) {
        return new MonotonicClockWrapper(clock);
    }

    public static final class MonotonicClockWrapper implements MonotonicClock {
        private long mLast;
        private final Clock provider;

        private MonotonicClockWrapper(Clock clock) {
            this.provider = clock;
            this.mLast = clock.now();
        }

        @Override // com.facebook.common.time.MonotonicClock
        public long nowNanos() {
            return TimeUnit.MILLISECONDS.toNanos(now());
        }

        @Override // com.facebook.common.time.MonotonicClock
        public long now() {
            long jMax = Math.max(this.mLast, this.provider.now());
            this.mLast = jMax;
            return jMax;
        }
    }
}
