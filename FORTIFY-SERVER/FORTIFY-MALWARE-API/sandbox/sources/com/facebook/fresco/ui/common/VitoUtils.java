package com.facebook.fresco.ui.common;

import java.util.concurrent.atomic.AtomicLong;
import kotlin.Metadata;
import kotlin.jvm.JvmStatic;

/* compiled from: VitoUtils.kt */
@Metadata(d1 = {"\u0000 \n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\t\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0002\bÆ\u0002\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003J\b\u0010\u0006\u001a\u00020\u0007H\u0007J\u0010\u0010\b\u001a\u00020\t2\u0006\u0010\n\u001a\u00020\u0007H\u0007R\u000e\u0010\u0004\u001a\u00020\u0005X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\u000b"}, d2 = {"Lcom/facebook/fresco/ui/common/VitoUtils;", "", "<init>", "()V", "idCounter", "Ljava/util/concurrent/atomic/AtomicLong;", "generateIdentifier", "", "getStringId", "", "id", "ui-common_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class VitoUtils {
    public static final VitoUtils INSTANCE = new VitoUtils();
    private static final AtomicLong idCounter = new AtomicLong();

    private VitoUtils() {
    }

    @JvmStatic
    public static final long generateIdentifier() {
        return idCounter.incrementAndGet();
    }

    @JvmStatic
    public static final String getStringId(long id) {
        return "v" + id;
    }
}
