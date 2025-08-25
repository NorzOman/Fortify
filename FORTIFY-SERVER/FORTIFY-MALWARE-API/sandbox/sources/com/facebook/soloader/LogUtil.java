package com.facebook.soloader;

import android.os.Build;
import android.util.Log;

/* loaded from: classes.dex */
public class LogUtil {
    private LogUtil() {
    }

    public static void e(String str, String str2, Throwable th) {
        Log.e(str, str2, th);
    }

    public static void e(String str, String str2) {
        Log.e(str, str2);
    }

    public static void w(String str, String str2, Throwable th) {
        Log.w(str, str2, th);
    }

    public static void w(String str, String str2) {
        Log.w(str, str2);
    }

    public static void i(String str, String str2, Throwable th) {
        if (isLoggable(str, 4)) {
            Log.i(str, str2, th);
        }
    }

    public static void i(String str, String str2) {
        if (isLoggable(str, 4)) {
            Log.i(str, str2);
        }
    }

    public static void d(String str, String str2, Throwable th) {
        if (isLoggable(str, 3)) {
            Log.d(str, str2, th);
        }
    }

    public static void d(String str, String str2) {
        if (isLoggable(str, 3)) {
            Log.d(str, str2);
        }
    }

    public static void v(String str, String str2, Throwable th) {
        if (isLoggable(str, 2)) {
            Log.v(str, str2, th);
        }
    }

    public static void v(String str, String str2) {
        if (isLoggable(str, 2)) {
            Log.v(str, str2);
        }
    }

    private static boolean isLoggable(String str, int i) {
        if (Build.VERSION.SDK_INT <= 25 && str.length() > 23) {
            return Log.isLoggable(str.substring(0, 23), i);
        }
        return Log.isLoggable(str, i);
    }
}
