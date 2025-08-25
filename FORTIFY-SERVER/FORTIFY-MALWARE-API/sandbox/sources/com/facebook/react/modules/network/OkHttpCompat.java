package com.facebook.react.modules.network;

import java.util.Collections;
import java.util.Map;
import okhttp3.Headers;
import okhttp3.OkHttpClient;

/* loaded from: classes.dex */
public class OkHttpCompat {
    public static CookieJarContainer getCookieJarContainer(OkHttpClient okHttpClient) {
        return (CookieJarContainer) okHttpClient.cookieJar();
    }

    public static Headers getHeadersFromMap(Map<String, String> map) {
        if (map == null) {
            return Headers.of((Map<String, String>) Collections.emptyMap());
        }
        return Headers.of(map);
    }
}
