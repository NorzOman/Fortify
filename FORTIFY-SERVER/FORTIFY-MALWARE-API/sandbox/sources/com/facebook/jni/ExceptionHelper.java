package com.facebook.jni;

import java.io.PrintWriter;
import java.io.StringWriter;

/* loaded from: classes.dex */
class ExceptionHelper {
    ExceptionHelper() {
    }

    private static String getErrorDescription(Throwable th) {
        StringWriter stringWriter = new StringWriter();
        th.printStackTrace(new PrintWriter(stringWriter));
        return stringWriter.toString();
    }
}
