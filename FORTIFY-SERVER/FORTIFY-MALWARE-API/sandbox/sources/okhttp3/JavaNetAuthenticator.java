package okhttp3;

import java.io.IOException;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: JavaNetAuthenticator.kt */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000\u001e\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\u0018\u00002\u00020\u0001B\u0005¢\u0006\u0002\u0010\u0002J\u001c\u0010\u0003\u001a\u0004\u0018\u00010\u00042\b\u0010\u0005\u001a\u0004\u0018\u00010\u00062\u0006\u0010\u0007\u001a\u00020\bH\u0016¨\u0006\t"}, d2 = {"Lokhttp3/JavaNetAuthenticator;", "Lokhttp3/Authenticator;", "()V", "authenticate", "Lokhttp3/Request;", "route", "Lokhttp3/Route;", "response", "Lokhttp3/Response;", "okhttp-urlconnection"}, k = 1, mv = {1, 4, 0})
/* loaded from: classes2.dex */
public final class JavaNetAuthenticator implements Authenticator {
    @Override // okhttp3.Authenticator
    public Request authenticate(Route route, Response response) throws IOException {
        Intrinsics.checkNotNullParameter(response, "response");
        return Authenticator.JAVA_NET_AUTHENTICATOR.authenticate(route, response);
    }
}
