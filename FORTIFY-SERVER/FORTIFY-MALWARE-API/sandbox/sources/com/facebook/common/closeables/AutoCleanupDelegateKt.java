package com.facebook.common.closeables;

import java.io.Closeable;
import java.io.IOException;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: AutoCleanupDelegate.kt */
@Metadata(d1 = {"\u0000\u0010\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0000\"\u001a\u0010\u0000\u001a\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00030\u0001X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\u0004"}, d2 = {"closeableCleanupFunction", "Lkotlin/Function1;", "Ljava/io/Closeable;", "", "fbcore_release"}, k = 2, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class AutoCleanupDelegateKt {
    private static final Function1<Closeable, Unit> closeableCleanupFunction = new Function1() { // from class: com.facebook.common.closeables.AutoCleanupDelegateKt$$ExternalSyntheticLambda0
        @Override // kotlin.jvm.functions.Function1
        public final Object invoke(Object obj) {
            return AutoCleanupDelegateKt.closeableCleanupFunction$lambda$0((Closeable) obj);
        }
    };

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit closeableCleanupFunction$lambda$0(Closeable it) throws IOException {
        Intrinsics.checkNotNullParameter(it, "it");
        it.close();
        return Unit.INSTANCE;
    }
}
