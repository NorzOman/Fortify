package com.facebook.fresco.ui.common;

import kotlin.Deprecated;
import kotlin.Metadata;
import kotlin.ReplaceWith;

/* compiled from: LegacyOnFadeListener.kt */
@Deprecated(message = "Please use the OnFadeListener directly", replaceWith = @ReplaceWith(expression = "OnFadeListener", imports = {"import com.facebook.fresco.ui.common.OnFadeListener"}))
@Metadata(d1 = {"\u0000\u0018\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0002\bg\u0018\u00002\u00020\u0001J\u0010\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u0005H&J\u0010\u0010\u0006\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u0005H&¨\u0006\u0007"}, d2 = {"Lcom/facebook/fresco/ui/common/LegacyOnFadeListener;", "", "onFadeStarted", "", "id", "", "onFadeFinished", "ui-common_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public interface LegacyOnFadeListener {
    void onFadeFinished(String id);

    void onFadeStarted(String id);
}
