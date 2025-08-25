package com.facebook.drawee.interfaces;

import android.net.Uri;
import javax.annotation.Nullable;

/* loaded from: classes.dex */
public interface SimpleDraweeControllerBuilder {
    DraweeController build();

    SimpleDraweeControllerBuilder setCallerContext(Object obj);

    SimpleDraweeControllerBuilder setOldController(@Nullable DraweeController draweeController);

    SimpleDraweeControllerBuilder setUri(Uri uri);

    SimpleDraweeControllerBuilder setUri(@Nullable String str);
}
