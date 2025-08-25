package com.facebook.react.common.network;

import kotlin.Metadata;
import kotlin.jvm.JvmStatic;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.Call;
import okhttp3.Dispatcher;
import okhttp3.OkHttpClient;

/* compiled from: OkHttpCallUtil.kt */
@Metadata(d1 = {"\u0000\u001a\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\bÀ\u0002\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003J\u0018\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u00072\u0006\u0010\b\u001a\u00020\u0001H\u0007¨\u0006\t"}, d2 = {"Lcom/facebook/react/common/network/OkHttpCallUtil;", "", "<init>", "()V", "cancelTag", "", "client", "Lokhttp3/OkHttpClient;", "tag", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class OkHttpCallUtil {
    public static final OkHttpCallUtil INSTANCE = new OkHttpCallUtil();

    private OkHttpCallUtil() {
    }

    @JvmStatic
    public static final void cancelTag(OkHttpClient client, Object tag) {
        Intrinsics.checkNotNullParameter(client, "client");
        Intrinsics.checkNotNullParameter(tag, "tag");
        Dispatcher dispatcher = client.getDispatcher();
        for (Call call : dispatcher.queuedCalls()) {
            if (Intrinsics.areEqual(tag, call.request().tag())) {
                call.cancel();
                return;
            }
        }
        for (Call call2 : dispatcher.runningCalls()) {
            if (Intrinsics.areEqual(tag, call2.request().tag())) {
                call2.cancel();
                return;
            }
        }
    }
}
