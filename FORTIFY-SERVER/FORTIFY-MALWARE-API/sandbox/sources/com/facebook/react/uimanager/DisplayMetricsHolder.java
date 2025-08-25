package com.facebook.react.uimanager;

import android.content.Context;
import android.util.DisplayMetrics;
import android.view.WindowManager;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.bridge.WritableNativeMap;
import kotlin.Metadata;
import kotlin.jvm.JvmStatic;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: DisplayMetricsHolder.kt */
@Metadata(d1 = {"\u00008\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0006\n\u0002\b\u0002\bÆ\u0002\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003J\b\u0010\u000b\u001a\u00020\u0007H\u0007J\u0012\u0010\f\u001a\u00020\r2\b\u0010\u000e\u001a\u0004\u0018\u00010\u0007H\u0007J\b\u0010\u000f\u001a\u00020\u0007H\u0007J\u0012\u0010\u0010\u001a\u00020\r2\b\u0010\u000e\u001a\u0004\u0018\u00010\u0007H\u0007J\u0010\u0010\u0011\u001a\u00020\r2\u0006\u0010\u0012\u001a\u00020\u0013H\u0007J\u0010\u0010\u0014\u001a\u00020\r2\u0006\u0010\u0012\u001a\u00020\u0013H\u0007J\u0010\u0010\u0015\u001a\u00020\u00162\u0006\u0010\u0017\u001a\u00020\u0018H\u0007J\u0018\u0010\u0019\u001a\u00020\u00162\u0006\u0010\u000e\u001a\u00020\u00072\u0006\u0010\u0017\u001a\u00020\u0018H\u0002R\u000e\u0010\u0004\u001a\u00020\u0005X\u0082T¢\u0006\u0002\n\u0000R\u001a\u0010\u0006\u001a\u0004\u0018\u00010\u00078\u0002@\u0002X\u0083\u000e¢\u0006\b\n\u0000\u0012\u0004\b\b\u0010\u0003R\u001a\u0010\t\u001a\u0004\u0018\u00010\u00078\u0002@\u0002X\u0083\u000e¢\u0006\b\n\u0000\u0012\u0004\b\n\u0010\u0003¨\u0006\u001a"}, d2 = {"Lcom/facebook/react/uimanager/DisplayMetricsHolder;", "", "<init>", "()V", "INITIALIZATION_MISSING_MESSAGE", "", "windowDisplayMetrics", "Landroid/util/DisplayMetrics;", "getWindowDisplayMetrics$annotations", "screenDisplayMetrics", "getScreenDisplayMetrics$annotations", "getWindowDisplayMetrics", "setWindowDisplayMetrics", "", "displayMetrics", "getScreenDisplayMetrics", "setScreenDisplayMetrics", "initDisplayMetricsIfNotInitialized", "context", "Landroid/content/Context;", "initDisplayMetrics", "getDisplayMetricsWritableMap", "Lcom/facebook/react/bridge/WritableMap;", "fontScale", "", "getPhysicalPixelsWritableMap", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class DisplayMetricsHolder {
    private static final String INITIALIZATION_MISSING_MESSAGE = "DisplayMetricsHolder must be initialized with initDisplayMetricsIfNotInitialized or initDisplayMetrics";
    public static final DisplayMetricsHolder INSTANCE = new DisplayMetricsHolder();
    private static DisplayMetrics screenDisplayMetrics;
    private static DisplayMetrics windowDisplayMetrics;

    @JvmStatic
    private static /* synthetic */ void getScreenDisplayMetrics$annotations() {
    }

    @JvmStatic
    private static /* synthetic */ void getWindowDisplayMetrics$annotations() {
    }

    private DisplayMetricsHolder() {
    }

    @JvmStatic
    public static final DisplayMetrics getWindowDisplayMetrics() {
        DisplayMetrics displayMetrics = windowDisplayMetrics;
        if (displayMetrics == null) {
            throw new IllegalStateException(INITIALIZATION_MISSING_MESSAGE.toString());
        }
        Intrinsics.checkNotNull(displayMetrics, "null cannot be cast to non-null type android.util.DisplayMetrics");
        return displayMetrics;
    }

    @JvmStatic
    public static final void setWindowDisplayMetrics(DisplayMetrics displayMetrics) {
        windowDisplayMetrics = displayMetrics;
    }

    @JvmStatic
    public static final DisplayMetrics getScreenDisplayMetrics() {
        DisplayMetrics displayMetrics = screenDisplayMetrics;
        if (displayMetrics == null) {
            throw new IllegalStateException(INITIALIZATION_MISSING_MESSAGE.toString());
        }
        Intrinsics.checkNotNull(displayMetrics, "null cannot be cast to non-null type android.util.DisplayMetrics");
        return displayMetrics;
    }

    @JvmStatic
    public static final void setScreenDisplayMetrics(DisplayMetrics displayMetrics) {
        screenDisplayMetrics = displayMetrics;
    }

    @JvmStatic
    public static final void initDisplayMetricsIfNotInitialized(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        if (screenDisplayMetrics != null) {
            return;
        }
        initDisplayMetrics(context);
    }

    @JvmStatic
    public static final void initDisplayMetrics(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        DisplayMetrics displayMetrics = context.getResources().getDisplayMetrics();
        windowDisplayMetrics = displayMetrics;
        DisplayMetrics displayMetrics2 = new DisplayMetrics();
        displayMetrics2.setTo(displayMetrics);
        Object systemService = context.getSystemService("window");
        Intrinsics.checkNotNull(systemService, "null cannot be cast to non-null type android.view.WindowManager");
        ((WindowManager) systemService).getDefaultDisplay().getRealMetrics(displayMetrics2);
        screenDisplayMetrics = displayMetrics2;
    }

    @JvmStatic
    public static final WritableMap getDisplayMetricsWritableMap(double fontScale) {
        DisplayMetricsHolder displayMetricsHolder = INSTANCE;
        if (windowDisplayMetrics == null) {
            throw new IllegalStateException(INITIALIZATION_MISSING_MESSAGE.toString());
        }
        if (screenDisplayMetrics == null) {
            throw new IllegalStateException(INITIALIZATION_MISSING_MESSAGE.toString());
        }
        WritableNativeMap writableNativeMap = new WritableNativeMap();
        DisplayMetrics displayMetrics = windowDisplayMetrics;
        Intrinsics.checkNotNull(displayMetrics, "null cannot be cast to non-null type android.util.DisplayMetrics");
        writableNativeMap.putMap("windowPhysicalPixels", displayMetricsHolder.getPhysicalPixelsWritableMap(displayMetrics, fontScale));
        DisplayMetrics displayMetrics2 = screenDisplayMetrics;
        Intrinsics.checkNotNull(displayMetrics2, "null cannot be cast to non-null type android.util.DisplayMetrics");
        writableNativeMap.putMap("screenPhysicalPixels", displayMetricsHolder.getPhysicalPixelsWritableMap(displayMetrics2, fontScale));
        return writableNativeMap;
    }

    private final WritableMap getPhysicalPixelsWritableMap(DisplayMetrics displayMetrics, double fontScale) {
        WritableNativeMap writableNativeMap = new WritableNativeMap();
        writableNativeMap.putInt("width", displayMetrics.widthPixels);
        writableNativeMap.putInt("height", displayMetrics.heightPixels);
        writableNativeMap.putDouble("scale", displayMetrics.density);
        writableNativeMap.putDouble("fontScale", fontScale);
        writableNativeMap.putDouble("densityDpi", displayMetrics.densityDpi);
        return writableNativeMap;
    }
}
