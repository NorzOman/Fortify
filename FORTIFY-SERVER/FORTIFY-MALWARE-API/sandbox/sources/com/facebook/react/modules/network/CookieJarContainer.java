package com.facebook.react.modules.network;

import kotlin.Metadata;
import okhttp3.CookieJar;

/* compiled from: CookieJarContainer.kt */
@Metadata(d1 = {"\u0000\u0012\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0003\bf\u0018\u00002\u00020\u0001J\u0010\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u0001H&J\b\u0010\u0005\u001a\u00020\u0003H&ø\u0001\u0000\u0082\u0002\u0006\n\u0004\b!0\u0001¨\u0006\u0006À\u0006\u0001"}, d2 = {"Lcom/facebook/react/modules/network/CookieJarContainer;", "Lokhttp3/CookieJar;", "setCookieJar", "", "cookieJar", "removeCookieJar", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public interface CookieJarContainer extends CookieJar {
    void removeCookieJar();

    void setCookieJar(CookieJar cookieJar);
}
