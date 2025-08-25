package com.facebook.react.bridge;

import kotlin.Metadata;
import kotlin.jvm.JvmStatic;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: ReactIgnorableMountingException.kt */
@Metadata(d1 = {"\u0000\u001e\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0003\n\u0002\u0010\u0003\n\u0002\b\u0004\u0018\u0000 \u000b2\u00060\u0001j\u0002`\u0002:\u0001\u000bB\u0011\b\u0016\u0012\u0006\u0010\u0003\u001a\u00020\u0004¢\u0006\u0004\b\u0005\u0010\u0006B\u0011\b\u0016\u0012\u0006\u0010\u0007\u001a\u00020\b¢\u0006\u0004\b\u0005\u0010\tB\u0019\b\u0016\u0012\u0006\u0010\u0003\u001a\u00020\u0004\u0012\u0006\u0010\u0007\u001a\u00020\b¢\u0006\u0004\b\u0005\u0010\n¨\u0006\f"}, d2 = {"Lcom/facebook/react/bridge/ReactIgnorableMountingException;", "Ljava/lang/RuntimeException;", "Lkotlin/RuntimeException;", "m", "", "<init>", "(Ljava/lang/String;)V", "e", "", "(Ljava/lang/Throwable;)V", "(Ljava/lang/String;Ljava/lang/Throwable;)V", "Companion", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class ReactIgnorableMountingException extends RuntimeException {

    /* renamed from: Companion, reason: from kotlin metadata */
    public static final Companion INSTANCE = new Companion(null);

    @JvmStatic
    public static final boolean isIgnorable(Throwable th) {
        return INSTANCE.isIgnorable(th);
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public ReactIgnorableMountingException(String m) {
        super(m);
        Intrinsics.checkNotNullParameter(m, "m");
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public ReactIgnorableMountingException(Throwable e) {
        super(e);
        Intrinsics.checkNotNullParameter(e, "e");
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public ReactIgnorableMountingException(String m, Throwable e) {
        super(m, e);
        Intrinsics.checkNotNullParameter(m, "m");
        Intrinsics.checkNotNullParameter(e, "e");
    }

    /* compiled from: ReactIgnorableMountingException.kt */
    @Metadata(d1 = {"\u0000\u0018\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u0003\n\u0000\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003J\u0010\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u0007H\u0007¨\u0006\b"}, d2 = {"Lcom/facebook/react/bridge/ReactIgnorableMountingException$Companion;", "", "<init>", "()V", "isIgnorable", "", "e", "", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }

        @JvmStatic
        public final boolean isIgnorable(Throwable e) {
            Intrinsics.checkNotNullParameter(e, "e");
            while (e != null) {
                if (e instanceof ReactIgnorableMountingException) {
                    return true;
                }
                e = e.getCause();
            }
            return false;
        }
    }
}
