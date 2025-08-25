package com.facebook.react.bridge;

/* loaded from: classes.dex */
public abstract class GuardedRunnable implements Runnable {
    private final JSExceptionHandler mExceptionHandler;

    public abstract void runGuarded();

    public GuardedRunnable(ReactContext reactContext) {
        this(reactContext.getExceptionHandler());
    }

    public GuardedRunnable(JSExceptionHandler jSExceptionHandler) {
        this.mExceptionHandler = jSExceptionHandler;
    }

    @Override // java.lang.Runnable
    public final void run() {
        try {
            runGuarded();
        } catch (RuntimeException e) {
            this.mExceptionHandler.handleException(e);
        }
    }
}
