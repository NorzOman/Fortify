package com.facebook.imagepipeline.datasource;

import android.graphics.Bitmap;
import com.facebook.common.references.CloseableReference;
import com.facebook.datasource.BaseDataSubscriber;
import com.facebook.datasource.DataSource;
import com.facebook.imagepipeline.image.CloseableBitmap;
import com.facebook.imagepipeline.image.CloseableImage;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import javax.annotation.Nullable;

/* loaded from: classes.dex */
public abstract class BaseListBitmapDataSubscriber extends BaseDataSubscriber<List<CloseableReference<CloseableImage>>> {
    protected abstract void onNewResultListImpl(@Nullable List<Bitmap> list);

    @Override // com.facebook.datasource.BaseDataSubscriber
    public void onNewResultImpl(DataSource<List<CloseableReference<CloseableImage>>> dataSource) {
        if (dataSource.isFinished()) {
            List<CloseableReference<CloseableImage>> result = dataSource.getResult();
            if (result == null) {
                onNewResultListImpl(null);
                return;
            }
            try {
                ArrayList arrayList = new ArrayList(result.size());
                for (CloseableReference<CloseableImage> closeableReference : result) {
                    if (closeableReference != null && (closeableReference.get() instanceof CloseableBitmap)) {
                        arrayList.add(((CloseableBitmap) closeableReference.get()).getUnderlyingBitmap());
                    } else {
                        arrayList.add(null);
                    }
                }
                onNewResultListImpl(arrayList);
            } finally {
                Iterator<CloseableReference<CloseableImage>> it = result.iterator();
                while (it.hasNext()) {
                    CloseableReference.closeSafely(it.next());
                }
            }
        }
    }
}
