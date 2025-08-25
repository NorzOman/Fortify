package com.facebook.react.packagerconnection;

import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import com.facebook.common.logging.FLog;
import com.facebook.react.modules.systeminfo.AndroidInfoHelpers;
import java.util.LinkedHashMap;
import java.util.Map;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: PackagerConnectionSettings.kt */
@Metadata(d1 = {"\u00008\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0003\n\u0002\u0010%\n\u0002\b\u0006\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0010$\n\u0002\b\u0004\b\u0016\u0018\u0000 \u001b2\u00020\u0001:\u0001\u001bB\u000f\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0004\b\u0004\u0010\u0005J\u0016\u0010\u0013\u001a\u00020\u00142\u0006\u0010\u0015\u001a\u00020\t2\u0006\u0010\u0016\u001a\u00020\tR\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\u0006\u001a\u00020\u0007X\u0082\u0004¢\u0006\u0002\n\u0000R\u0011\u0010\b\u001a\u00020\t¢\u0006\b\n\u0000\u001a\u0004\b\n\u0010\u000bR\u001a\u0010\f\u001a\u000e\u0012\u0004\u0012\u00020\t\u0012\u0004\u0012\u00020\t0\rX\u0082\u0004¢\u0006\u0002\n\u0000R$\u0010\u000f\u001a\u00020\t2\u0006\u0010\u000e\u001a\u00020\t8V@VX\u0096\u000e¢\u0006\f\u001a\u0004\b\u0010\u0010\u000b\"\u0004\b\u0011\u0010\u0012R\u001d\u0010\u0017\u001a\u000e\u0012\u0004\u0012\u00020\t\u0012\u0004\u0012\u00020\t0\u00188F¢\u0006\u0006\u001a\u0004\b\u0019\u0010\u001a¨\u0006\u001c"}, d2 = {"Lcom/facebook/react/packagerconnection/PackagerConnectionSettings;", "", "appContext", "Landroid/content/Context;", "<init>", "(Landroid/content/Context;)V", "preferences", "Landroid/content/SharedPreferences;", "packageName", "", "getPackageName", "()Ljava/lang/String;", "_additionalOptionsForPackager", "", "host", "debugServerHost", "getDebugServerHost", "setDebugServerHost", "(Ljava/lang/String;)V", "setAdditionalOptionForPackager", "", "key", "value", "additionalOptionsForPackager", "", "getAdditionalOptionsForPackager", "()Ljava/util/Map;", "Companion", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public class PackagerConnectionSettings {
    private static final String PREFS_DEBUG_SERVER_HOST_KEY = "debug_http_host";
    private final Map<String, String> _additionalOptionsForPackager;
    private final Context appContext;
    private final String packageName;
    private final SharedPreferences preferences;
    private static final Companion Companion = new Companion(null);
    private static final String TAG = "PackagerConnectionSettings";

    public PackagerConnectionSettings(Context appContext) {
        Intrinsics.checkNotNullParameter(appContext, "appContext");
        this.appContext = appContext;
        SharedPreferences defaultSharedPreferences = PreferenceManager.getDefaultSharedPreferences(appContext);
        Intrinsics.checkNotNullExpressionValue(defaultSharedPreferences, "getDefaultSharedPreferences(...)");
        this.preferences = defaultSharedPreferences;
        String packageName = appContext.getPackageName();
        Intrinsics.checkNotNullExpressionValue(packageName, "getPackageName(...)");
        this.packageName = packageName;
        this._additionalOptionsForPackager = new LinkedHashMap();
    }

    public final String getPackageName() {
        return this.packageName;
    }

    public String getDebugServerHost() {
        String string = this.preferences.getString(PREFS_DEBUG_SERVER_HOST_KEY, null);
        if (string != null && string.length() > 0) {
            return string;
        }
        String serverHost = AndroidInfoHelpers.getServerHost(this.appContext);
        if (Intrinsics.areEqual(serverHost, AndroidInfoHelpers.DEVICE_LOCALHOST)) {
            FLog.w(TAG, "You seem to be running on device. Run '" + AndroidInfoHelpers.getAdbReverseTcpCommand(this.appContext) + "' to forward the debug server's port to the device.");
        }
        return serverHost;
    }

    public void setDebugServerHost(String host) {
        Intrinsics.checkNotNullParameter(host, "host");
        this.preferences.edit().putString(PREFS_DEBUG_SERVER_HOST_KEY, host).apply();
    }

    public final void setAdditionalOptionForPackager(String key, String value) {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(value, "value");
        this._additionalOptionsForPackager.put(key, value);
    }

    public final Map<String, String> getAdditionalOptionsForPackager() {
        return this._additionalOptionsForPackager;
    }

    /* compiled from: PackagerConnectionSettings.kt */
    @Metadata(d1 = {"\u0000\u0014\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0002\b\u0004\b\u0082\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003R\u0018\u0010\u0004\u001a\n \u0006*\u0004\u0018\u00010\u00050\u0005X\u0082\u0004¢\u0006\u0004\n\u0002\u0010\u0007R\u000e\u0010\b\u001a\u00020\u0005X\u0082T¢\u0006\u0002\n\u0000¨\u0006\t"}, d2 = {"Lcom/facebook/react/packagerconnection/PackagerConnectionSettings$Companion;", "", "<init>", "()V", "TAG", "", "kotlin.jvm.PlatformType", "Ljava/lang/String;", "PREFS_DEBUG_SERVER_HOST_KEY", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
    private static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }
    }
}
