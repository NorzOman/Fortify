package com.facebook.react.bridge;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: JavaJSExecutor.kt */
@Metadata(d1 = {"\u0000\u001a\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\t\bg\u0018\u00002\u00020\u0001:\u0002\r\u000eJ\b\u0010\u0002\u001a\u00020\u0003H&J\u0010\u0010\u0004\u001a\u00020\u00032\u0006\u0010\u0005\u001a\u00020\u0006H'J\u001c\u0010\u0007\u001a\u0004\u0018\u00010\u00062\u0006\u0010\b\u001a\u00020\u00062\b\u0010\t\u001a\u0004\u0018\u00010\u0006H'J\u0018\u0010\n\u001a\u00020\u00032\u0006\u0010\u000b\u001a\u00020\u00062\u0006\u0010\f\u001a\u00020\u0006H'ø\u0001\u0000\u0082\u0002\u0006\n\u0004\b!0\u0001¨\u0006\u000fÀ\u0006\u0001"}, d2 = {"Lcom/facebook/react/bridge/JavaJSExecutor;", "", "close", "", "loadBundle", "sourceURL", "", "executeJSCall", "methodName", "jsonArgsArray", "setGlobalVariable", "propertyName", "jsonEncodedValue", "Factory", "ProxyExecutorException", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public interface JavaJSExecutor {

    /* compiled from: JavaJSExecutor.kt */
    @Metadata(d1 = {"\u0000\u0010\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0000\bf\u0018\u00002\u00020\u0001J\n\u0010\u0002\u001a\u0004\u0018\u00010\u0003H&ø\u0001\u0000\u0082\u0002\u0006\n\u0004\b!0\u0001¨\u0006\u0004À\u0006\u0001"}, d2 = {"Lcom/facebook/react/bridge/JavaJSExecutor$Factory;", "", "create", "Lcom/facebook/react/bridge/JavaJSExecutor;", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
    public interface Factory {
        JavaJSExecutor create() throws Exception;
    }

    void close();

    String executeJSCall(String methodName, String jsonArgsArray) throws ProxyExecutorException;

    void loadBundle(String sourceURL) throws ProxyExecutorException;

    void setGlobalVariable(String propertyName, String jsonEncodedValue);

    /* compiled from: JavaJSExecutor.kt */
    @Metadata(d1 = {"\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0003\n\u0002\b\u0003\u0018\u00002\u00060\u0001j\u0002`\u0002B\u000f\u0012\u0006\u0010\u0003\u001a\u00020\u0004¢\u0006\u0004\b\u0005\u0010\u0006¨\u0006\u0007"}, d2 = {"Lcom/facebook/react/bridge/JavaJSExecutor$ProxyExecutorException;", "Ljava/lang/Exception;", "Lkotlin/Exception;", "cause", "", "<init>", "(Ljava/lang/Throwable;)V", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
    public static final class ProxyExecutorException extends Exception {
        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public ProxyExecutorException(Throwable cause) {
            super(cause);
            Intrinsics.checkNotNullParameter(cause, "cause");
        }
    }
}
