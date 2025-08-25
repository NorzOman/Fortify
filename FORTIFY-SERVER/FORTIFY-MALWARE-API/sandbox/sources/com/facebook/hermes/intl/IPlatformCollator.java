package com.facebook.hermes.intl;

/* loaded from: classes.dex */
public interface IPlatformCollator {
    int compare(String str, String str2);

    IPlatformCollator configure(ILocaleObject<?> iLocaleObject) throws JSRangeErrorException;

    String[] getAvailableLocales();

    Sensitivity getSensitivity();

    IPlatformCollator setCaseFirstAttribute(CaseFirst caseFirst);

    IPlatformCollator setIgnorePunctuation(boolean z);

    IPlatformCollator setNumericAttribute(boolean z);

    IPlatformCollator setSensitivity(Sensitivity sensitivity);

    public enum Sensitivity {
        BASE,
        ACCENT,
        CASE,
        VARIANT,
        LOCALE;

        @Override // java.lang.Enum
        public String toString() {
            int i = AnonymousClass1.$SwitchMap$com$facebook$hermes$intl$IPlatformCollator$Sensitivity[ordinal()];
            if (i == 1) {
                return Constants.SENSITIVITY_BASE;
            }
            if (i == 2) {
                return Constants.SENSITIVITY_ACCENT;
            }
            if (i == 3) {
                return Constants.SENSITIVITY_CASE;
            }
            if (i == 4) {
                return Constants.SENSITIVITY_VARIANT;
            }
            if (i == 5) {
                return "";
            }
            throw new IllegalArgumentException();
        }
    }

    public enum Usage {
        SORT,
        SEARCH;

        @Override // java.lang.Enum
        public String toString() {
            int i = AnonymousClass1.$SwitchMap$com$facebook$hermes$intl$IPlatformCollator$Usage[ordinal()];
            if (i == 1) {
                return Constants.SORT;
            }
            if (i == 2) {
                return "search";
            }
            throw new IllegalArgumentException();
        }
    }

    /* renamed from: com.facebook.hermes.intl.IPlatformCollator$1, reason: invalid class name */
    static /* synthetic */ class AnonymousClass1 {
        static final /* synthetic */ int[] $SwitchMap$com$facebook$hermes$intl$IPlatformCollator$CaseFirst;
        static final /* synthetic */ int[] $SwitchMap$com$facebook$hermes$intl$IPlatformCollator$Sensitivity;
        static final /* synthetic */ int[] $SwitchMap$com$facebook$hermes$intl$IPlatformCollator$Usage;

        static {
            int[] iArr = new int[CaseFirst.values().length];
            $SwitchMap$com$facebook$hermes$intl$IPlatformCollator$CaseFirst = iArr;
            try {
                iArr[CaseFirst.UPPER.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformCollator$CaseFirst[CaseFirst.LOWER.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformCollator$CaseFirst[CaseFirst.FALSE.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            int[] iArr2 = new int[Usage.values().length];
            $SwitchMap$com$facebook$hermes$intl$IPlatformCollator$Usage = iArr2;
            try {
                iArr2[Usage.SORT.ordinal()] = 1;
            } catch (NoSuchFieldError unused4) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformCollator$Usage[Usage.SEARCH.ordinal()] = 2;
            } catch (NoSuchFieldError unused5) {
            }
            int[] iArr3 = new int[Sensitivity.values().length];
            $SwitchMap$com$facebook$hermes$intl$IPlatformCollator$Sensitivity = iArr3;
            try {
                iArr3[Sensitivity.BASE.ordinal()] = 1;
            } catch (NoSuchFieldError unused6) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformCollator$Sensitivity[Sensitivity.ACCENT.ordinal()] = 2;
            } catch (NoSuchFieldError unused7) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformCollator$Sensitivity[Sensitivity.CASE.ordinal()] = 3;
            } catch (NoSuchFieldError unused8) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformCollator$Sensitivity[Sensitivity.VARIANT.ordinal()] = 4;
            } catch (NoSuchFieldError unused9) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformCollator$Sensitivity[Sensitivity.LOCALE.ordinal()] = 5;
            } catch (NoSuchFieldError unused10) {
            }
        }
    }

    public enum CaseFirst {
        UPPER,
        LOWER,
        FALSE;

        @Override // java.lang.Enum
        public String toString() {
            int i = AnonymousClass1.$SwitchMap$com$facebook$hermes$intl$IPlatformCollator$CaseFirst[ordinal()];
            if (i == 1) {
                return Constants.CASEFIRST_UPPER;
            }
            if (i == 2) {
                return Constants.CASEFIRST_LOWER;
            }
            if (i == 3) {
                return Constants.CASEFIRST_FALSE;
            }
            throw new IllegalArgumentException();
        }
    }
}
