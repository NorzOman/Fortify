package com.facebook.imagepipeline.decoder;

import com.facebook.imagepipeline.image.EncodedImage;
import com.facebook.react.devsupport.StackTraceHelper;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: DecodeException.kt */
@Metadata(d1 = {"\u0000$\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u0003\n\u0002\b\u0004\u0018\u00002\u00060\u0002j\u0002`\u0001B\u001b\b\u0016\u0012\b\u0010\u0003\u001a\u0004\u0018\u00010\u0004\u0012\u0006\u0010\u0005\u001a\u00020\u0006¢\u0006\u0004\b\u0007\u0010\bB%\b\u0016\u0012\b\u0010\u0003\u001a\u0004\u0018\u00010\u0004\u0012\b\u0010\t\u001a\u0004\u0018\u00010\n\u0012\u0006\u0010\u0005\u001a\u00020\u0006¢\u0006\u0004\b\u0007\u0010\u000bR\u0011\u0010\u0005\u001a\u00020\u0006¢\u0006\b\n\u0000\u001a\u0004\b\f\u0010\r¨\u0006\u000e"}, d2 = {"Lcom/facebook/imagepipeline/decoder/DecodeException;", "Lkotlin/RuntimeException;", "Ljava/lang/RuntimeException;", StackTraceHelper.MESSAGE_KEY, "", "encodedImage", "Lcom/facebook/imagepipeline/image/EncodedImage;", "<init>", "(Ljava/lang/String;Lcom/facebook/imagepipeline/image/EncodedImage;)V", "t", "", "(Ljava/lang/String;Ljava/lang/Throwable;Lcom/facebook/imagepipeline/image/EncodedImage;)V", "getEncodedImage", "()Lcom/facebook/imagepipeline/image/EncodedImage;", "imagepipeline_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class DecodeException extends RuntimeException {
    private final EncodedImage encodedImage;

    public final EncodedImage getEncodedImage() {
        return this.encodedImage;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public DecodeException(String str, EncodedImage encodedImage) {
        super(str);
        Intrinsics.checkNotNullParameter(encodedImage, "encodedImage");
        this.encodedImage = encodedImage;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public DecodeException(String str, Throwable th, EncodedImage encodedImage) {
        super(str, th);
        Intrinsics.checkNotNullParameter(encodedImage, "encodedImage");
        this.encodedImage = encodedImage;
    }
}
