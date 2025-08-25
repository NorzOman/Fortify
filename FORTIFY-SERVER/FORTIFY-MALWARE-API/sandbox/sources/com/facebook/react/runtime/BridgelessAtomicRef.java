package com.facebook.react.runtime;

import com.facebook.infer.annotation.Assertions;
import java.util.Objects;

/* loaded from: classes.dex */
class BridgelessAtomicRef<T> {
    private volatile String failureMessage;
    T mInitialValue;
    volatile T mValue;
    private volatile State state;

    interface Provider<T> {
        T get();
    }

    enum State {
        Init,
        Creating,
        Success,
        Failure
    }

    public BridgelessAtomicRef(T t) {
        this.mValue = t;
        this.mInitialValue = t;
        this.state = State.Init;
        this.failureMessage = "";
    }

    public BridgelessAtomicRef() {
        this(null);
    }

    public T getOrCreate(Provider<T> provider) {
        boolean z;
        T t;
        T t2;
        synchronized (this) {
            if (this.state == State.Success) {
                return get();
            }
            if (this.state == State.Failure) {
                throw new RuntimeException("BridgelessAtomicRef: Failed to create object. Reason: " + this.failureMessage);
            }
            boolean z2 = false;
            if (this.state != State.Creating) {
                this.state = State.Creating;
                z = true;
            } else {
                z = false;
            }
            if (z) {
                try {
                    this.mValue = provider.get();
                    synchronized (this) {
                        this.state = State.Success;
                        notifyAll();
                        t = get();
                    }
                    return t;
                } catch (RuntimeException e) {
                    synchronized (this) {
                        this.state = State.Failure;
                        this.failureMessage = Objects.toString(e.getMessage(), "null");
                        notifyAll();
                        throw new RuntimeException("BridgelessAtomicRef: Failed to create object.", e);
                    }
                }
            }
            synchronized (this) {
                while (this.state == State.Creating) {
                    try {
                        wait();
                    } catch (InterruptedException unused) {
                        z2 = true;
                    }
                }
                if (z2) {
                    Thread.currentThread().interrupt();
                }
                if (this.state == State.Failure) {
                    throw new RuntimeException("BridgelessAtomicRef: Failed to create object. Reason: " + this.failureMessage);
                }
                t2 = get();
            }
            return t2;
        }
    }

    public synchronized T getAndReset() {
        T t;
        t = get();
        reset();
        return t;
    }

    public synchronized void reset() {
        this.mValue = this.mInitialValue;
        this.state = State.Init;
        this.failureMessage = "";
    }

    public synchronized T get() {
        return (T) Assertions.assertNotNull(this.mValue);
    }

    public synchronized T getNullable() {
        return this.mValue;
    }
}
