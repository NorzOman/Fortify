package com.facebook.common.util;

/* loaded from: classes.dex */
public class ExceptionWithNoStacktrace extends Exception {
    @Override // java.lang.Throwable
    public synchronized Throwable fillInStackTrace() {
        return this;
    }

    public ExceptionWithNoStacktrace(String str) {
        super(str);
    }
}
