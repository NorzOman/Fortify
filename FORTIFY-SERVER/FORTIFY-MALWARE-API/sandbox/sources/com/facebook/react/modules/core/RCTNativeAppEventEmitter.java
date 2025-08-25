package com.facebook.react.modules.core;

import com.facebook.common.util.UriUtil;
import com.facebook.react.bridge.JavaScriptModule;
import kotlin.Metadata;

/* compiled from: RCTNativeAppEventEmitter.kt */
@Metadata(d1 = {"\u0000\u001c\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0000\n\u0000\bç\u0080\u0001\u0018\u00002\u00020\u0001J\u001a\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u00052\b\u0010\u0006\u001a\u0004\u0018\u00010\u0007H&ø\u0001\u0000\u0082\u0002\u0006\n\u0004\b!0\u0001¨\u0006\bÀ\u0006\u0001"}, d2 = {"Lcom/facebook/react/modules/core/RCTNativeAppEventEmitter;", "Lcom/facebook/react/bridge/JavaScriptModule;", "emit", "", "eventName", "", UriUtil.DATA_SCHEME, "", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public interface RCTNativeAppEventEmitter extends JavaScriptModule {
    void emit(String eventName, Object data);
}
