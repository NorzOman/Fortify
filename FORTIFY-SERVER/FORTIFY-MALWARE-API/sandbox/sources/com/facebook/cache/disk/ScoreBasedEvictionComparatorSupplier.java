package com.facebook.cache.disk;

import com.facebook.cache.disk.DiskStorage;

/* loaded from: classes.dex */
public class ScoreBasedEvictionComparatorSupplier implements EntryEvictionComparatorSupplier {
    private final float mAgeWeight;
    private final float mSizeWeight;

    public ScoreBasedEvictionComparatorSupplier(float f, float f2) {
        this.mAgeWeight = f;
        this.mSizeWeight = f2;
    }

    @Override // com.facebook.cache.disk.EntryEvictionComparatorSupplier
    public EntryEvictionComparator get() {
        return new EntryEvictionComparator() { // from class: com.facebook.cache.disk.ScoreBasedEvictionComparatorSupplier.1
            long now = System.currentTimeMillis();

            @Override // java.util.Comparator
            public int compare(DiskStorage.Entry entry, DiskStorage.Entry entry2) {
                float fCalculateScore = ScoreBasedEvictionComparatorSupplier.this.calculateScore(entry, this.now);
                float fCalculateScore2 = ScoreBasedEvictionComparatorSupplier.this.calculateScore(entry2, this.now);
                if (fCalculateScore < fCalculateScore2) {
                    return 1;
                }
                return fCalculateScore2 == fCalculateScore ? 0 : -1;
            }
        };
    }

    float calculateScore(DiskStorage.Entry entry, long j) {
        return (this.mAgeWeight * (j - entry.getTimestamp())) + (this.mSizeWeight * entry.getSize());
    }
}
