package com.facebook.soloader.recovery;

import com.facebook.soloader.SoSource;

/* loaded from: classes.dex */
public class CompositeRecoveryStrategy implements RecoveryStrategy {
    private int mCurrentStrategy = 0;
    private final RecoveryStrategy[] mStrategies;

    public CompositeRecoveryStrategy(RecoveryStrategy... recoveryStrategyArr) {
        this.mStrategies = recoveryStrategyArr;
    }

    @Override // com.facebook.soloader.recovery.RecoveryStrategy
    public boolean recover(UnsatisfiedLinkError unsatisfiedLinkError, SoSource[] soSourceArr) {
        int i;
        RecoveryStrategy[] recoveryStrategyArr;
        do {
            i = this.mCurrentStrategy;
            recoveryStrategyArr = this.mStrategies;
            if (i >= recoveryStrategyArr.length) {
                return false;
            }
            this.mCurrentStrategy = i + 1;
        } while (!recoveryStrategyArr[i].recover(unsatisfiedLinkError, soSourceArr));
        return true;
    }
}
