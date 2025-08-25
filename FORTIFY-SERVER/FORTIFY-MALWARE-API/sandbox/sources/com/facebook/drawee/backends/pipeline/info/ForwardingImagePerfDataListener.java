package com.facebook.drawee.backends.pipeline.info;

import com.facebook.fresco.ui.common.ImageLoadStatus;
import com.facebook.fresco.ui.common.ImagePerfData;
import com.facebook.fresco.ui.common.ImagePerfDataListener;
import com.facebook.fresco.ui.common.VisibilityState;
import java.util.Collection;
import java.util.Iterator;

/* loaded from: classes.dex */
public class ForwardingImagePerfDataListener implements ImagePerfDataListener {
    private final Collection<ImagePerfDataListener> mListeners;

    public ForwardingImagePerfDataListener(Collection<ImagePerfDataListener> collection) {
        this.mListeners = collection;
    }

    @Override // com.facebook.fresco.ui.common.ImagePerfDataListener
    public void onImageLoadStatusUpdated(ImagePerfData imagePerfData, ImageLoadStatus imageLoadStatus) {
        Iterator<ImagePerfDataListener> it = this.mListeners.iterator();
        while (it.hasNext()) {
            it.next().onImageLoadStatusUpdated(imagePerfData, imageLoadStatus);
        }
    }

    @Override // com.facebook.fresco.ui.common.ImagePerfDataListener
    public void onImageVisibilityUpdated(ImagePerfData imagePerfData, VisibilityState visibilityState) {
        Iterator<ImagePerfDataListener> it = this.mListeners.iterator();
        while (it.hasNext()) {
            it.next().onImageVisibilityUpdated(imagePerfData, visibilityState);
        }
    }
}
