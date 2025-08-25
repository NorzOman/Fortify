package com.facebook.datasource;

import com.facebook.common.executors.CallerThreadExecutor;
import com.facebook.common.internal.Supplier;
import java.util.Collections;
import java.util.Set;
import java.util.WeakHashMap;
import javax.annotation.Nullable;

/* loaded from: classes.dex */
public class RetainingDataSourceSupplier<T> implements Supplier<DataSource<T>> {
    private final Set<RetainingDataSource> mDataSources = Collections.newSetFromMap(new WeakHashMap());

    @Nullable
    private Supplier<DataSource<T>> mCurrentDataSourceSupplier = null;

    @Override // com.facebook.common.internal.Supplier
    public DataSource<T> get() {
        RetainingDataSource retainingDataSource = new RetainingDataSource();
        retainingDataSource.setSupplier(this.mCurrentDataSourceSupplier);
        this.mDataSources.add(retainingDataSource);
        return retainingDataSource;
    }

    public void replaceSupplier(Supplier<DataSource<T>> supplier) {
        this.mCurrentDataSourceSupplier = supplier;
        for (RetainingDataSource retainingDataSource : this.mDataSources) {
            if (!retainingDataSource.isClosed()) {
                retainingDataSource.setSupplier(supplier);
            }
        }
    }

    private static class RetainingDataSource<T> extends AbstractDataSource<T> {

        @Nullable
        private DataSource<T> mDataSource;

        /* JADX INFO: Access modifiers changed from: private */
        public void onDataSourceFailed() {
        }

        @Override // com.facebook.datasource.AbstractDataSource, com.facebook.datasource.DataSource
        public boolean hasMultipleResults() {
            return true;
        }

        private RetainingDataSource() {
            this.mDataSource = null;
        }

        public void setSupplier(@Nullable Supplier<DataSource<T>> supplier) {
            if (isClosed()) {
                return;
            }
            DataSource<T> dataSource = supplier != null ? supplier.get() : null;
            synchronized (this) {
                if (isClosed()) {
                    closeSafely(dataSource);
                    return;
                }
                DataSource<T> dataSource2 = this.mDataSource;
                this.mDataSource = dataSource;
                if (dataSource != null) {
                    dataSource.subscribe(new InternalDataSubscriber(), CallerThreadExecutor.getInstance());
                }
                closeSafely(dataSource2);
            }
        }

        @Override // com.facebook.datasource.AbstractDataSource, com.facebook.datasource.DataSource
        @Nullable
        public synchronized T getResult() {
            DataSource<T> dataSource;
            dataSource = this.mDataSource;
            return dataSource != null ? dataSource.getResult() : null;
        }

        /* JADX WARN: Removed duplicated region for block: B:8:0x000d  */
        @Override // com.facebook.datasource.AbstractDataSource, com.facebook.datasource.DataSource
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public synchronized boolean hasResult() {
            /*
                r1 = this;
                monitor-enter(r1)
                com.facebook.datasource.DataSource<T> r0 = r1.mDataSource     // Catch: java.lang.Throwable -> L10
                if (r0 == 0) goto Ld
                boolean r0 = r0.hasResult()     // Catch: java.lang.Throwable -> L10
                if (r0 == 0) goto Ld
                r0 = 1
                goto Le
            Ld:
                r0 = 0
            Le:
                monitor-exit(r1)
                return r0
            L10:
                r0 = move-exception
                monitor-exit(r1)     // Catch: java.lang.Throwable -> L10
                throw r0
            */
            throw new UnsupportedOperationException("Method not decompiled: com.facebook.datasource.RetainingDataSourceSupplier.RetainingDataSource.hasResult():boolean");
        }

        @Override // com.facebook.datasource.AbstractDataSource, com.facebook.datasource.DataSource
        public boolean close() {
            synchronized (this) {
                if (!super.close()) {
                    return false;
                }
                DataSource<T> dataSource = this.mDataSource;
                this.mDataSource = null;
                closeSafely(dataSource);
                return true;
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void onDataSourceNewResult(DataSource<T> dataSource) {
            if (dataSource == this.mDataSource) {
                setResult(null, false, dataSource.getExtras());
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void onDatasourceProgress(DataSource<T> dataSource) {
            if (dataSource == this.mDataSource) {
                setProgress(dataSource.getProgress());
            }
        }

        private static <T> void closeSafely(DataSource<T> dataSource) {
            if (dataSource != null) {
                dataSource.close();
            }
        }

        private class InternalDataSubscriber implements DataSubscriber<T> {
            @Override // com.facebook.datasource.DataSubscriber
            public void onCancellation(DataSource<T> dataSource) {
            }

            private InternalDataSubscriber() {
            }

            @Override // com.facebook.datasource.DataSubscriber
            public void onNewResult(DataSource<T> dataSource) {
                if (dataSource.hasResult()) {
                    RetainingDataSource.this.onDataSourceNewResult(dataSource);
                } else if (dataSource.isFinished()) {
                    RetainingDataSource.this.onDataSourceFailed();
                }
            }

            @Override // com.facebook.datasource.DataSubscriber
            public void onFailure(DataSource<T> dataSource) {
                RetainingDataSource.this.onDataSourceFailed();
            }

            @Override // com.facebook.datasource.DataSubscriber
            public void onProgressUpdate(DataSource<T> dataSource) {
                RetainingDataSource.this.onDatasourceProgress(dataSource);
            }
        }
    }
}
