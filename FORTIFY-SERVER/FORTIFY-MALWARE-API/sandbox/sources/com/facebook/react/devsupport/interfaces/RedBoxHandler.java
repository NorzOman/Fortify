package com.facebook.react.devsupport.interfaces;

import android.content.Context;
import android.text.SpannedString;
import com.facebook.react.devsupport.StackTraceHelper;
import kotlin.Metadata;

/* compiled from: RedBoxHandler.kt */
@Metadata(d1 = {"\u0000@\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0011\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\bf\u0018\u00002\u00020\u0001:\u0001\u0015J-\u0010\u0002\u001a\u00020\u00032\b\u0010\u0004\u001a\u0004\u0018\u00010\u00052\f\u0010\u0006\u001a\b\u0012\u0004\u0012\u00020\b0\u00072\u0006\u0010\t\u001a\u00020\nH&¢\u0006\u0002\u0010\u000bJ\b\u0010\f\u001a\u00020\rH&J;\u0010\u000e\u001a\u00020\u00032\u0006\u0010\u000f\u001a\u00020\u00102\u0006\u0010\u0004\u001a\u00020\u00052\f\u0010\u0006\u001a\b\u0012\u0004\u0012\u00020\b0\u00072\u0006\u0010\u0011\u001a\u00020\u00052\u0006\u0010\u0012\u001a\u00020\u0013H&¢\u0006\u0002\u0010\u0014ø\u0001\u0000\u0082\u0002\u0006\n\u0004\b!0\u0001¨\u0006\u0016À\u0006\u0001"}, d2 = {"Lcom/facebook/react/devsupport/interfaces/RedBoxHandler;", "", "handleRedbox", "", "title", "", StackTraceHelper.STACK_KEY, "", "Lcom/facebook/react/devsupport/interfaces/StackFrame;", "errorType", "Lcom/facebook/react/devsupport/interfaces/ErrorType;", "(Ljava/lang/String;[Lcom/facebook/react/devsupport/interfaces/StackFrame;Lcom/facebook/react/devsupport/interfaces/ErrorType;)V", "isReportEnabled", "", "reportRedbox", "context", "Landroid/content/Context;", "sourceUrl", "reportCompletedListener", "Lcom/facebook/react/devsupport/interfaces/RedBoxHandler$ReportCompletedListener;", "(Landroid/content/Context;Ljava/lang/String;[Lcom/facebook/react/devsupport/interfaces/StackFrame;Ljava/lang/String;Lcom/facebook/react/devsupport/interfaces/RedBoxHandler$ReportCompletedListener;)V", "ReportCompletedListener", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public interface RedBoxHandler {

    /* compiled from: RedBoxHandler.kt */
    @Metadata(d1 = {"\u0000\u0018\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\bf\u0018\u00002\u00020\u0001J\u0012\u0010\u0002\u001a\u00020\u00032\b\u0010\u0004\u001a\u0004\u0018\u00010\u0005H&J\u0012\u0010\u0006\u001a\u00020\u00032\b\u0010\u0004\u001a\u0004\u0018\u00010\u0005H&ø\u0001\u0000\u0082\u0002\u0006\n\u0004\b!0\u0001¨\u0006\u0007À\u0006\u0001"}, d2 = {"Lcom/facebook/react/devsupport/interfaces/RedBoxHandler$ReportCompletedListener;", "", "onReportSuccess", "", "spannedString", "Landroid/text/SpannedString;", "onReportError", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
    public interface ReportCompletedListener {
        void onReportError(SpannedString spannedString);

        void onReportSuccess(SpannedString spannedString);
    }

    void handleRedbox(String title, StackFrame[] stack, ErrorType errorType);

    boolean isReportEnabled();

    void reportRedbox(Context context, String title, StackFrame[] stack, String sourceUrl, ReportCompletedListener reportCompletedListener);
}
