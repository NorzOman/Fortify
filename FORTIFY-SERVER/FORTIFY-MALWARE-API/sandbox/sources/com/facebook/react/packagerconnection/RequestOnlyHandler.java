package com.facebook.react.packagerconnection;

import com.facebook.common.logging.FLog;
import kotlin.Metadata;

/* compiled from: RequestOnlyHandler.kt */
@Metadata(d1 = {"\u0000 \n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0000\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\b&\u0018\u00002\u00020\u0001B\u0007¢\u0006\u0004\b\u0002\u0010\u0003J\u001a\u0010\u0004\u001a\u00020\u00052\b\u0010\u0006\u001a\u0004\u0018\u00010\u00072\u0006\u0010\b\u001a\u00020\tH&J\u0010\u0010\n\u001a\u00020\u00052\b\u0010\u0006\u001a\u0004\u0018\u00010\u0007¨\u0006\u000b"}, d2 = {"Lcom/facebook/react/packagerconnection/RequestOnlyHandler;", "Lcom/facebook/react/packagerconnection/RequestHandler;", "<init>", "()V", "onRequest", "", "params", "", "responder", "Lcom/facebook/react/packagerconnection/Responder;", "onNotification", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public abstract class RequestOnlyHandler implements RequestHandler {
    @Override // com.facebook.react.packagerconnection.RequestHandler
    public abstract void onRequest(Object params, Responder responder);

    @Override // com.facebook.react.packagerconnection.RequestHandler
    public final void onNotification(Object params) {
        FLog.e("JSPackagerClient", "Notification is not supported");
    }
}
