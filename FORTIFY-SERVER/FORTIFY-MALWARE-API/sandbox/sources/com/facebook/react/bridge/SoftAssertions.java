package com.facebook.react.bridge;

import com.facebook.react.bridge.ReactSoftExceptionLogger;
import com.facebook.react.devsupport.StackTraceHelper;
import kotlin.Metadata;
import kotlin.jvm.JvmStatic;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: SoftAssertions.kt */
@Metadata(d1 = {"\u0000\"\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0002\b\u0005\bÆ\u0002\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003J\u0010\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u0007H\u0007J\u0018\u0010\b\u001a\u00020\u00052\u0006\u0010\t\u001a\u00020\n2\u0006\u0010\u0006\u001a\u00020\u0007H\u0007J\u001f\u0010\u000b\u001a\u0004\u0018\u0001H\f\"\u0004\b\u0000\u0010\f2\b\u0010\r\u001a\u0004\u0018\u0001H\fH\u0007¢\u0006\u0002\u0010\u000e¨\u0006\u000f"}, d2 = {"Lcom/facebook/react/bridge/SoftAssertions;", "", "<init>", "()V", "assertUnreachable", "", StackTraceHelper.MESSAGE_KEY, "", "assertCondition", "condition", "", "assertNotNull", "T", "instance", "(Ljava/lang/Object;)Ljava/lang/Object;", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class SoftAssertions {
    public static final SoftAssertions INSTANCE = new SoftAssertions();

    private SoftAssertions() {
    }

    @JvmStatic
    public static final void assertUnreachable(String message) {
        Intrinsics.checkNotNullParameter(message, "message");
        ReactSoftExceptionLogger.logSoftException(ReactSoftExceptionLogger.Categories.SOFT_ASSERTIONS, new AssertionException(message));
    }

    @JvmStatic
    public static final void assertCondition(boolean condition, String message) {
        Intrinsics.checkNotNullParameter(message, "message");
        if (condition) {
            return;
        }
        ReactSoftExceptionLogger.logSoftException(ReactSoftExceptionLogger.Categories.SOFT_ASSERTIONS, new AssertionException(message));
    }

    @JvmStatic
    public static final <T> T assertNotNull(T instance) {
        if (instance == null) {
            ReactSoftExceptionLogger.logSoftException(ReactSoftExceptionLogger.Categories.SOFT_ASSERTIONS, new AssertionException("Expected object to not be null!"));
        }
        return instance;
    }
}
