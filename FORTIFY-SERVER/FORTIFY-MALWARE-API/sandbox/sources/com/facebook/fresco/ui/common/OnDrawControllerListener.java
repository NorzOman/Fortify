package com.facebook.fresco.ui.common;

import kotlin.Metadata;

/* compiled from: OnDrawControllerListener.kt */
@Metadata(d1 = {"\u0000\"\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\bæ\u0080\u0001\u0018\u0000*\u0004\b\u0000\u0010\u00012\u00020\u0002J%\u0010\u0003\u001a\u00020\u00042\u0006\u0010\u0005\u001a\u00020\u00062\u0006\u0010\u0007\u001a\u00028\u00002\u0006\u0010\b\u001a\u00020\tH&¢\u0006\u0002\u0010\n¨\u0006\u000b"}, d2 = {"Lcom/facebook/fresco/ui/common/OnDrawControllerListener;", "INFO", "", "onImageDrawn", "", "id", "", "imageInfo", "dimensionsInfo", "Lcom/facebook/fresco/ui/common/DimensionsInfo;", "(Ljava/lang/String;Ljava/lang/Object;Lcom/facebook/fresco/ui/common/DimensionsInfo;)V", "ui-common_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public interface OnDrawControllerListener<INFO> {
    void onImageDrawn(String id, INFO imageInfo, DimensionsInfo dimensionsInfo);
}
