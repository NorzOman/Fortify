package com.facebook.soloader.observer;

import androidx.lifecycle.LifecycleKt$$ExternalSyntheticBackportWithForwarding0;
import com.facebook.soloader.SoFileLoader;
import com.facebook.soloader.SoSource;
import com.facebook.soloader.recovery.RecoveryStrategy;
import java.util.concurrent.atomic.AtomicReference;
import javax.annotation.Nullable;

/* loaded from: classes.dex */
public class ObserverHolder {
    private static final AtomicReference<Observer[]> sObservers = new AtomicReference<>();

    public static void resetObserversForTestsOnly() {
        sObservers.set(null);
    }

    public static void addObserver(Observer observer) {
        AtomicReference<Observer[]> atomicReference;
        Observer[] observerArr;
        Observer[] observerArr2;
        do {
            atomicReference = sObservers;
            observerArr = atomicReference.get();
            if (observerArr == null) {
                observerArr2 = new Observer[]{observer};
            } else {
                observerArr2 = new Observer[observerArr.length + 1];
                System.arraycopy(observerArr, 0, observerArr2, 0, observerArr.length);
                observerArr2[observerArr.length] = observer;
            }
        } while (!LifecycleKt$$ExternalSyntheticBackportWithForwarding0.m(atomicReference, observerArr, observerArr2));
    }

    public static void onLoadLibraryStart(String str, @Nullable String str2, int i) {
        Observer[] observerArr = sObservers.get();
        if (observerArr != null) {
            for (Observer observer : observerArr) {
                observer.onLoadLibraryStart(str, str2, i);
            }
        }
    }

    public static void onLoadLibraryEnd(@Nullable Throwable th, boolean z) {
        Observer[] observerArr = sObservers.get();
        if (observerArr != null) {
            for (Observer observer : observerArr) {
                observer.onLoadLibraryEnd(th, z);
            }
        }
    }

    public static void onLoadDependencyStart(String str, int i) {
        Observer[] observerArr = sObservers.get();
        if (observerArr != null) {
            for (Observer observer : observerArr) {
                observer.onLoadDependencyStart(str, i);
            }
        }
    }

    public static void onLoadDependencyEnd(@Nullable Throwable th, boolean z) {
        Observer[] observerArr = sObservers.get();
        if (observerArr != null) {
            for (Observer observer : observerArr) {
                observer.onLoadDependencyEnd(th, z);
            }
        }
    }

    public static void onSoSourceLoadLibraryStart(SoSource soSource) {
        Observer[] observerArr = sObservers.get();
        if (observerArr != null) {
            for (Observer observer : observerArr) {
                observer.onSoSourceLoadLibraryStart(soSource);
            }
        }
    }

    public static void onSoSourceLoadLibraryEnd(@Nullable Throwable th) {
        Observer[] observerArr = sObservers.get();
        if (observerArr != null) {
            for (Observer observer : observerArr) {
                observer.onSoSourceLoadLibraryEnd(th);
            }
        }
    }

    public static void onRecoveryStart(RecoveryStrategy recoveryStrategy) {
        Observer[] observerArr = sObservers.get();
        if (observerArr != null) {
            for (Observer observer : observerArr) {
                observer.onRecoveryStart(recoveryStrategy);
            }
        }
    }

    public static void onRecoveryEnd(@Nullable Throwable th) {
        Observer[] observerArr = sObservers.get();
        if (observerArr != null) {
            for (Observer observer : observerArr) {
                observer.onRecoveryEnd(th);
            }
        }
    }

    public static void onGetDependenciesStart() {
        Observer[] observerArr = sObservers.get();
        if (observerArr != null) {
            for (Observer observer : observerArr) {
                observer.onGetDependenciesStart();
            }
        }
    }

    public static void onGetDependenciesEnd(@Nullable Throwable th) {
        Observer[] observerArr = sObservers.get();
        if (observerArr != null) {
            for (Observer observer : observerArr) {
                observer.onGetDependenciesEnd(th);
            }
        }
    }

    public static void onSoFileLoaderLoadStart(SoFileLoader soFileLoader, String str, int i) {
        Observer[] observerArr = sObservers.get();
        if (observerArr != null) {
            for (Observer observer : observerArr) {
                observer.onSoFileLoaderLoadStart(soFileLoader, str, i);
            }
        }
    }

    public static void onSoFileLoaderLoadEnd(@Nullable Throwable th) {
        Observer[] observerArr = sObservers.get();
        if (observerArr != null) {
            for (Observer observer : observerArr) {
                observer.onSoFileLoaderLoadEnd(th);
            }
        }
    }
}
