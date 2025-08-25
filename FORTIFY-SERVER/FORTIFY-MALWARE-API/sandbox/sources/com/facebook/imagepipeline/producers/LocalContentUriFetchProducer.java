package com.facebook.imagepipeline.producers;

import android.content.ContentResolver;
import android.content.res.AssetFileDescriptor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.provider.ContactsContract;
import com.facebook.common.memory.PooledByteBufferFactory;
import com.facebook.common.util.UriUtil;
import com.facebook.imagepipeline.image.EncodedImage;
import com.facebook.imagepipeline.request.ImageRequest;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.Executor;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* compiled from: LocalContentUriFetchProducer.kt */
@Metadata(d1 = {"\u0000:\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0002\u0018\u0000 \u00132\u00020\u0001:\u0001\u0013B\u001f\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0005\u0012\u0006\u0010\u0006\u001a\u00020\u0007¢\u0006\u0004\b\b\u0010\tJ\u0012\u0010\n\u001a\u0004\u0018\u00010\u000b2\u0006\u0010\f\u001a\u00020\rH\u0014J\u0012\u0010\u000e\u001a\u0004\u0018\u00010\u000b2\u0006\u0010\u000f\u001a\u00020\u0010H\u0002J\b\u0010\u0011\u001a\u00020\u0012H\u0014R\u000e\u0010\u0006\u001a\u00020\u0007X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\u0014"}, d2 = {"Lcom/facebook/imagepipeline/producers/LocalContentUriFetchProducer;", "Lcom/facebook/imagepipeline/producers/LocalFetchProducer;", "executor", "Ljava/util/concurrent/Executor;", "pooledByteBufferFactory", "Lcom/facebook/common/memory/PooledByteBufferFactory;", "contentResolver", "Landroid/content/ContentResolver;", "<init>", "(Ljava/util/concurrent/Executor;Lcom/facebook/common/memory/PooledByteBufferFactory;Landroid/content/ContentResolver;)V", "getEncodedImage", "Lcom/facebook/imagepipeline/image/EncodedImage;", "imageRequest", "Lcom/facebook/imagepipeline/request/ImageRequest;", "getCameraImage", "uri", "Landroid/net/Uri;", "getProducerName", "", "Companion", "imagepipeline_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class LocalContentUriFetchProducer extends LocalFetchProducer {
    public static final String PRODUCER_NAME = "LocalContentUriFetchProducer";
    private final ContentResolver contentResolver;
    private static final String[] PROJECTION = {"_id", "_data"};

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public LocalContentUriFetchProducer(Executor executor, PooledByteBufferFactory pooledByteBufferFactory, ContentResolver contentResolver) {
        super(executor, pooledByteBufferFactory);
        Intrinsics.checkNotNullParameter(executor, "executor");
        Intrinsics.checkNotNullParameter(pooledByteBufferFactory, "pooledByteBufferFactory");
        Intrinsics.checkNotNullParameter(contentResolver, "contentResolver");
        this.contentResolver = contentResolver;
    }

    @Override // com.facebook.imagepipeline.producers.LocalFetchProducer
    protected EncodedImage getEncodedImage(ImageRequest imageRequest) throws IOException {
        EncodedImage cameraImage;
        FileInputStream fileInputStreamCreateInputStream;
        Intrinsics.checkNotNullParameter(imageRequest, "imageRequest");
        Uri sourceUri = imageRequest.getSourceUri();
        Intrinsics.checkNotNullExpressionValue(sourceUri, "getSourceUri(...)");
        if (UriUtil.isLocalContactUri(sourceUri)) {
            String string = sourceUri.toString();
            Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
            if (StringsKt.endsWith$default(string, "/photo", false, 2, (Object) null)) {
                fileInputStreamCreateInputStream = this.contentResolver.openInputStream(sourceUri);
            } else {
                String string2 = sourceUri.toString();
                Intrinsics.checkNotNullExpressionValue(string2, "toString(...)");
                if (StringsKt.endsWith$default(string2, "/display_photo", false, 2, (Object) null)) {
                    try {
                        AssetFileDescriptor assetFileDescriptorOpenAssetFileDescriptor = this.contentResolver.openAssetFileDescriptor(sourceUri, "r");
                        if (assetFileDescriptorOpenAssetFileDescriptor == null) {
                            throw new IllegalStateException("Required value was null.".toString());
                        }
                        fileInputStreamCreateInputStream = assetFileDescriptorOpenAssetFileDescriptor.createInputStream();
                    } catch (IOException unused) {
                        throw new IOException("Contact photo does not exist: " + sourceUri);
                    }
                } else {
                    InputStream inputStreamOpenContactPhotoInputStream = ContactsContract.Contacts.openContactPhotoInputStream(this.contentResolver, sourceUri);
                    if (inputStreamOpenContactPhotoInputStream == null) {
                        throw new IOException("Contact photo does not exist: " + sourceUri);
                    }
                    fileInputStreamCreateInputStream = inputStreamOpenContactPhotoInputStream;
                }
            }
            if (fileInputStreamCreateInputStream == null) {
                throw new IllegalStateException("Required value was null.".toString());
            }
            return getEncodedImage(fileInputStreamCreateInputStream, -1);
        }
        if (UriUtil.isLocalCameraUri(sourceUri) && (cameraImage = getCameraImage(sourceUri)) != null) {
            return cameraImage;
        }
        InputStream inputStreamOpenInputStream = this.contentResolver.openInputStream(sourceUri);
        if (inputStreamOpenInputStream != null) {
            return getEncodedImage(inputStreamOpenInputStream, -1);
        }
        throw new IllegalStateException("Required value was null.".toString());
    }

    private final EncodedImage getCameraImage(Uri uri) throws IOException {
        try {
            ParcelFileDescriptor parcelFileDescriptorOpenFileDescriptor = this.contentResolver.openFileDescriptor(uri, "r");
            if (parcelFileDescriptorOpenFileDescriptor == null) {
                throw new IllegalStateException("Required value was null.".toString());
            }
            EncodedImage encodedImage = getEncodedImage(new FileInputStream(parcelFileDescriptorOpenFileDescriptor.getFileDescriptor()), (int) parcelFileDescriptorOpenFileDescriptor.getStatSize());
            Intrinsics.checkNotNullExpressionValue(encodedImage, "getEncodedImage(...)");
            parcelFileDescriptorOpenFileDescriptor.close();
            return encodedImage;
        } catch (FileNotFoundException unused) {
            return null;
        }
    }

    @Override // com.facebook.imagepipeline.producers.LocalFetchProducer
    protected String getProducerName() {
        return PRODUCER_NAME;
    }
}
