package com.facebook.react.util;

import com.facebook.react.bridge.JavaScriptModule;
import com.facebook.react.devsupport.StackTraceHelper;
import kotlin.Metadata;

/* compiled from: RCTLog.kt */
@Metadata(d1 = {"\u0000\u0018\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0002\bf\u0018\u00002\u00020\u0001J\u001c\u0010\u0002\u001a\u00020\u00032\b\u0010\u0004\u001a\u0004\u0018\u00010\u00052\b\u0010\u0006\u001a\u0004\u0018\u00010\u0005H&ø\u0001\u0000\u0082\u0002\u0006\n\u0004\b!0\u0001¨\u0006\u0007À\u0006\u0001"}, d2 = {"Lcom/facebook/react/util/RCTLog;", "Lcom/facebook/react/bridge/JavaScriptModule;", "logIfNoNativeHook", "", "level", "", StackTraceHelper.MESSAGE_KEY, "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public interface RCTLog extends JavaScriptModule {
    void logIfNoNativeHook(String level, String message);
}
