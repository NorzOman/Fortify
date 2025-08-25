package com.facebook.react.packagerconnection;

/* loaded from: classes.dex */
public interface RequestHandler {
    void onNotification(Object obj);

    void onRequest(Object obj, Responder responder);
}
