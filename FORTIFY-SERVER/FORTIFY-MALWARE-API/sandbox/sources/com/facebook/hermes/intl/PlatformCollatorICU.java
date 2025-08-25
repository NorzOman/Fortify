package com.facebook.hermes.intl;

import android.icu.text.RuleBasedCollator;
import android.icu.util.ULocale;
import com.facebook.hermes.intl.IPlatformCollator;
import java.util.ArrayList;

/* loaded from: classes.dex */
public class PlatformCollatorICU implements IPlatformCollator {
    private RuleBasedCollator mCollator = null;

    PlatformCollatorICU() {
    }

    @Override // com.facebook.hermes.intl.IPlatformCollator
    public IPlatformCollator configure(ILocaleObject<?> iLocaleObject) throws JSRangeErrorException {
        RuleBasedCollator ruleBasedCollator = (RuleBasedCollator) RuleBasedCollator.getInstance(((LocaleObjectICU) iLocaleObject).getLocale());
        this.mCollator = ruleBasedCollator;
        ruleBasedCollator.setDecomposition(17);
        return this;
    }

    @Override // com.facebook.hermes.intl.IPlatformCollator
    public int compare(String str, String str2) {
        return this.mCollator.compare(str, str2);
    }

    @Override // com.facebook.hermes.intl.IPlatformCollator
    public IPlatformCollator.Sensitivity getSensitivity() {
        RuleBasedCollator ruleBasedCollator = this.mCollator;
        if (ruleBasedCollator == null) {
            return IPlatformCollator.Sensitivity.LOCALE;
        }
        int strength = ruleBasedCollator.getStrength();
        if (strength == 0) {
            return this.mCollator.isCaseLevel() ? IPlatformCollator.Sensitivity.CASE : IPlatformCollator.Sensitivity.BASE;
        }
        if (strength == 1) {
            return IPlatformCollator.Sensitivity.ACCENT;
        }
        return IPlatformCollator.Sensitivity.VARIANT;
    }

    @Override // com.facebook.hermes.intl.IPlatformCollator
    public IPlatformCollator setSensitivity(IPlatformCollator.Sensitivity sensitivity) {
        int i = AnonymousClass1.$SwitchMap$com$facebook$hermes$intl$IPlatformCollator$Sensitivity[sensitivity.ordinal()];
        if (i == 1) {
            this.mCollator.setStrength(0);
        } else if (i == 2) {
            this.mCollator.setStrength(1);
        } else if (i == 3) {
            this.mCollator.setStrength(0);
            this.mCollator.setCaseLevel(true);
        } else if (i == 4) {
            this.mCollator.setStrength(2);
        }
        return this;
    }

    @Override // com.facebook.hermes.intl.IPlatformCollator
    public IPlatformCollator setIgnorePunctuation(boolean z) {
        if (z) {
            this.mCollator.setAlternateHandlingShifted(true);
        }
        return this;
    }

    @Override // com.facebook.hermes.intl.IPlatformCollator
    public IPlatformCollator setNumericAttribute(boolean z) {
        if (z) {
            this.mCollator.setNumericCollation(JSObjects.getJavaBoolean(true));
        }
        return this;
    }

    /* renamed from: com.facebook.hermes.intl.PlatformCollatorICU$1, reason: invalid class name */
    static /* synthetic */ class AnonymousClass1 {
        static final /* synthetic */ int[] $SwitchMap$com$facebook$hermes$intl$IPlatformCollator$CaseFirst;
        static final /* synthetic */ int[] $SwitchMap$com$facebook$hermes$intl$IPlatformCollator$Sensitivity;

        static {
            int[] iArr = new int[IPlatformCollator.CaseFirst.values().length];
            $SwitchMap$com$facebook$hermes$intl$IPlatformCollator$CaseFirst = iArr;
            try {
                iArr[IPlatformCollator.CaseFirst.UPPER.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformCollator$CaseFirst[IPlatformCollator.CaseFirst.LOWER.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformCollator$CaseFirst[IPlatformCollator.CaseFirst.FALSE.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            int[] iArr2 = new int[IPlatformCollator.Sensitivity.values().length];
            $SwitchMap$com$facebook$hermes$intl$IPlatformCollator$Sensitivity = iArr2;
            try {
                iArr2[IPlatformCollator.Sensitivity.BASE.ordinal()] = 1;
            } catch (NoSuchFieldError unused4) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformCollator$Sensitivity[IPlatformCollator.Sensitivity.ACCENT.ordinal()] = 2;
            } catch (NoSuchFieldError unused5) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformCollator$Sensitivity[IPlatformCollator.Sensitivity.CASE.ordinal()] = 3;
            } catch (NoSuchFieldError unused6) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformCollator$Sensitivity[IPlatformCollator.Sensitivity.VARIANT.ordinal()] = 4;
            } catch (NoSuchFieldError unused7) {
            }
        }
    }

    @Override // com.facebook.hermes.intl.IPlatformCollator
    public IPlatformCollator setCaseFirstAttribute(IPlatformCollator.CaseFirst caseFirst) {
        int i = AnonymousClass1.$SwitchMap$com$facebook$hermes$intl$IPlatformCollator$CaseFirst[caseFirst.ordinal()];
        if (i == 1) {
            this.mCollator.setUpperCaseFirst(true);
        } else if (i == 2) {
            this.mCollator.setLowerCaseFirst(true);
        } else {
            this.mCollator.setCaseFirstDefault();
        }
        return this;
    }

    @Override // com.facebook.hermes.intl.IPlatformCollator
    public String[] getAvailableLocales() {
        ArrayList arrayList = new ArrayList();
        for (ULocale uLocale : ULocale.getAvailableLocales()) {
            arrayList.add(uLocale.toLanguageTag());
        }
        return (String[]) arrayList.toArray(new String[arrayList.size()]);
    }
}
