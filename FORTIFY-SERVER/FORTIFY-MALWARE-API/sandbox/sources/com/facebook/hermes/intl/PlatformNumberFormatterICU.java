package com.facebook.hermes.intl;

import android.icu.text.CompactDecimalFormat;
import android.icu.text.DecimalFormat;
import android.icu.text.DecimalFormatSymbols;
import android.icu.text.MeasureFormat;
import android.icu.text.NumberFormat;
import android.icu.text.NumberingSystem;
import android.icu.util.Currency;
import android.icu.util.Measure;
import android.icu.util.MeasureUnit;
import android.icu.util.ULocale;
import android.os.Build;
import com.facebook.hermes.intl.IPlatformNumberFormatter;
import java.text.AttributedCharacterIterator;
import java.text.Format;
import java.util.ArrayList;

/* loaded from: classes.dex */
public class PlatformNumberFormatterICU implements IPlatformNumberFormatter {
    private Format mFinalFormat;
    private LocaleObjectICU mLocaleObject;
    private MeasureUnit mMeasureUnit;
    private android.icu.text.NumberFormat mNumberFormat;
    private IPlatformNumberFormatter.Style mStyle;

    @Override // com.facebook.hermes.intl.IPlatformNumberFormatter
    public /* bridge */ /* synthetic */ IPlatformNumberFormatter configure(ILocaleObject iLocaleObject, String str, IPlatformNumberFormatter.Style style, IPlatformNumberFormatter.CurrencySign currencySign, IPlatformNumberFormatter.Notation notation, IPlatformNumberFormatter.CompactDisplay compactDisplay) throws JSRangeErrorException {
        return configure((ILocaleObject<?>) iLocaleObject, str, style, currencySign, notation, compactDisplay);
    }

    PlatformNumberFormatterICU() {
    }

    private void initialize(android.icu.text.NumberFormat numberFormat, ILocaleObject<?> iLocaleObject, IPlatformNumberFormatter.Style style) {
        this.mNumberFormat = numberFormat;
        this.mFinalFormat = numberFormat;
        this.mLocaleObject = (LocaleObjectICU) iLocaleObject;
        this.mStyle = style;
        numberFormat.setRoundingMode(4);
    }

    @Override // com.facebook.hermes.intl.IPlatformNumberFormatter
    public PlatformNumberFormatterICU setCurrency(String str, IPlatformNumberFormatter.CurrencyDisplay currencyDisplay) throws JSRangeErrorException {
        if (this.mStyle == IPlatformNumberFormatter.Style.CURRENCY) {
            Currency currency = Currency.getInstance(str);
            this.mNumberFormat.setCurrency(currency);
            if (currencyDisplay != IPlatformNumberFormatter.CurrencyDisplay.CODE) {
                str = currency.getName(this.mLocaleObject.getLocale(), currencyDisplay.getNameStyle(), (boolean[]) null);
            }
            android.icu.text.NumberFormat numberFormat = this.mNumberFormat;
            if (numberFormat instanceof DecimalFormat) {
                DecimalFormat decimalFormat = (DecimalFormat) numberFormat;
                DecimalFormatSymbols decimalFormatSymbols = decimalFormat.getDecimalFormatSymbols();
                decimalFormatSymbols.setCurrencySymbol(str);
                decimalFormat.setDecimalFormatSymbols(decimalFormatSymbols);
            }
        }
        return this;
    }

    @Override // com.facebook.hermes.intl.IPlatformNumberFormatter
    public PlatformNumberFormatterICU setGrouping(boolean z) {
        this.mNumberFormat.setGroupingUsed(z);
        return this;
    }

    @Override // com.facebook.hermes.intl.IPlatformNumberFormatter
    public PlatformNumberFormatterICU setMinIntergerDigits(int i) {
        if (i != -1) {
            this.mNumberFormat.setMinimumIntegerDigits(i);
        }
        return this;
    }

    @Override // com.facebook.hermes.intl.IPlatformNumberFormatter
    public PlatformNumberFormatterICU setSignificantDigits(IPlatformNumberFormatter.RoundingType roundingType, int i, int i2) throws JSRangeErrorException {
        if ((this.mNumberFormat instanceof DecimalFormat) && roundingType == IPlatformNumberFormatter.RoundingType.SIGNIFICANT_DIGITS) {
            DecimalFormat decimalFormat = (DecimalFormat) this.mNumberFormat;
            if (i >= 0) {
                decimalFormat.setMinimumSignificantDigits(i);
            }
            if (i2 >= 0) {
                if (i2 < decimalFormat.getMinimumSignificantDigits()) {
                    throw new JSRangeErrorException("maximumSignificantDigits should be at least equal to minimumSignificantDigits");
                }
                decimalFormat.setMaximumSignificantDigits(i2);
            }
            decimalFormat.setSignificantDigitsUsed(true);
        }
        return this;
    }

    @Override // com.facebook.hermes.intl.IPlatformNumberFormatter
    public PlatformNumberFormatterICU setFractionDigits(IPlatformNumberFormatter.RoundingType roundingType, int i, int i2) {
        if (roundingType == IPlatformNumberFormatter.RoundingType.FRACTION_DIGITS) {
            if (i >= 0) {
                this.mNumberFormat.setMinimumFractionDigits(i);
            }
            if (i2 >= 0) {
                this.mNumberFormat.setMaximumFractionDigits(i2);
            }
            android.icu.text.NumberFormat numberFormat = this.mNumberFormat;
            if (numberFormat instanceof DecimalFormat) {
                ((DecimalFormat) numberFormat).setSignificantDigitsUsed(false);
            }
        }
        return this;
    }

    @Override // com.facebook.hermes.intl.IPlatformNumberFormatter
    public PlatformNumberFormatterICU setSignDisplay(IPlatformNumberFormatter.SignDisplay signDisplay) {
        android.icu.text.NumberFormat numberFormat = this.mNumberFormat;
        if (numberFormat instanceof DecimalFormat) {
            DecimalFormat decimalFormat = (DecimalFormat) numberFormat;
            DecimalFormatSymbols decimalFormatSymbols = decimalFormat.getDecimalFormatSymbols();
            if (Build.VERSION.SDK_INT >= 31) {
                int i = AnonymousClass1.$SwitchMap$com$facebook$hermes$intl$IPlatformNumberFormatter$SignDisplay[signDisplay.ordinal()];
                if (i == 1) {
                    decimalFormat.setSignAlwaysShown(false);
                } else if (i == 2 || i == 3) {
                    decimalFormat.setSignAlwaysShown(true);
                }
            } else {
                int i2 = AnonymousClass1.$SwitchMap$com$facebook$hermes$intl$IPlatformNumberFormatter$SignDisplay[signDisplay.ordinal()];
                if (i2 == 1) {
                    decimalFormat.setPositivePrefix("");
                    decimalFormat.setPositiveSuffix("");
                    decimalFormat.setNegativePrefix("");
                    decimalFormat.setNegativeSuffix("");
                } else if (i2 == 2 || i2 == 3) {
                    if (!decimalFormat.getNegativePrefix().isEmpty()) {
                        decimalFormat.setPositivePrefix(new String(new char[]{decimalFormatSymbols.getPlusSign()}));
                    }
                    if (!decimalFormat.getNegativeSuffix().isEmpty()) {
                        decimalFormat.setPositiveSuffix(new String(new char[]{decimalFormatSymbols.getPlusSign()}));
                    }
                }
            }
        }
        return this;
    }

    /* renamed from: com.facebook.hermes.intl.PlatformNumberFormatterICU$1, reason: invalid class name */
    static /* synthetic */ class AnonymousClass1 {
        static final /* synthetic */ int[] $SwitchMap$com$facebook$hermes$intl$IPlatformNumberFormatter$SignDisplay;

        static {
            int[] iArr = new int[IPlatformNumberFormatter.SignDisplay.values().length];
            $SwitchMap$com$facebook$hermes$intl$IPlatformNumberFormatter$SignDisplay = iArr;
            try {
                iArr[IPlatformNumberFormatter.SignDisplay.NEVER.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformNumberFormatter$SignDisplay[IPlatformNumberFormatter.SignDisplay.ALWAYS.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformNumberFormatter$SignDisplay[IPlatformNumberFormatter.SignDisplay.EXCEPTZERO.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
        }
    }

    private static MeasureUnit parseUnit(String str) throws JSRangeErrorException {
        for (MeasureUnit measureUnit : MeasureUnit.getAvailable()) {
            if (measureUnit.getSubtype().equals(str) || measureUnit.getSubtype().equals(measureUnit.getType() + "-" + str)) {
                return measureUnit;
            }
        }
        throw new JSRangeErrorException("Unknown unit: " + str);
    }

    @Override // com.facebook.hermes.intl.IPlatformNumberFormatter
    public PlatformNumberFormatterICU setUnits(String str, IPlatformNumberFormatter.UnitDisplay unitDisplay) throws JSRangeErrorException {
        if (this.mStyle == IPlatformNumberFormatter.Style.UNIT) {
            this.mMeasureUnit = parseUnit(str);
            this.mFinalFormat = MeasureFormat.getInstance(this.mLocaleObject.getLocale(), unitDisplay.getFormatWidth(), this.mNumberFormat);
        }
        return this;
    }

    @Override // com.facebook.hermes.intl.IPlatformNumberFormatter
    public String format(double d) {
        try {
            try {
                Format format = this.mFinalFormat;
                if ((format instanceof MeasureFormat) && this.mMeasureUnit != null) {
                    return format.format(new Measure(Double.valueOf(d), this.mMeasureUnit));
                }
                return format.format(Double.valueOf(d));
            } catch (NumberFormatException unused) {
                return android.icu.text.NumberFormat.getInstance(ULocale.getDefault()).format(d);
            }
        } catch (RuntimeException unused2) {
            return android.icu.text.NumberFormat.getInstance(ULocale.forLanguageTag("en")).format(d);
        }
    }

    @Override // com.facebook.hermes.intl.IPlatformNumberFormatter
    public String fieldToString(AttributedCharacterIterator.Attribute attribute, double d) {
        if (attribute == NumberFormat.Field.SIGN) {
            if (Double.compare(d, 0.0d) >= 0) {
                return "plusSign";
            }
            return "minusSign";
        }
        if (attribute == NumberFormat.Field.INTEGER) {
            if (Double.isNaN(d)) {
                return "nan";
            }
            if (Double.isInfinite(d)) {
                return "infinity";
            }
            return "integer";
        }
        if (attribute == NumberFormat.Field.FRACTION) {
            return "fraction";
        }
        if (attribute == NumberFormat.Field.EXPONENT) {
            return "exponentInteger";
        }
        if (attribute == NumberFormat.Field.EXPONENT_SIGN) {
            return "exponentMinusSign";
        }
        if (attribute == NumberFormat.Field.EXPONENT_SYMBOL) {
            return "exponentSeparator";
        }
        if (attribute == NumberFormat.Field.DECIMAL_SEPARATOR) {
            return "decimal";
        }
        if (attribute == NumberFormat.Field.GROUPING_SEPARATOR) {
            return "group";
        }
        if (attribute == NumberFormat.Field.PERCENT) {
            return "percentSign";
        }
        if (attribute == NumberFormat.Field.PERMILLE) {
            return "permilleSign";
        }
        if (attribute == NumberFormat.Field.CURRENCY) {
            return "currency";
        }
        if (attribute.toString().equals("android.icu.text.NumberFormat$Field(compact)")) {
            return "compact";
        }
        return "literal";
    }

    @Override // com.facebook.hermes.intl.IPlatformNumberFormatter
    public AttributedCharacterIterator formatToParts(double d) {
        try {
            try {
                Format format = this.mFinalFormat;
                if ((format instanceof MeasureFormat) && this.mMeasureUnit != null) {
                    return format.formatToCharacterIterator(new Measure(Double.valueOf(d), this.mMeasureUnit));
                }
                return format.formatToCharacterIterator(Double.valueOf(d));
            } catch (RuntimeException unused) {
                return android.icu.text.NumberFormat.getInstance(ULocale.forLanguageTag("en")).formatToCharacterIterator(Double.valueOf(d));
            }
        } catch (NumberFormatException unused2) {
            return android.icu.text.NumberFormat.getInstance(ULocale.getDefault()).formatToCharacterIterator(Double.valueOf(d));
        } catch (Exception unused3) {
            return android.icu.text.NumberFormat.getInstance(ULocale.forLanguageTag("en")).formatToCharacterIterator(Double.valueOf(d));
        }
    }

    public static int getCurrencyDigits(String str) throws JSRangeErrorException {
        try {
            return Currency.getInstance(str).getDefaultFractionDigits();
        } catch (IllegalArgumentException unused) {
            throw new JSRangeErrorException("Invalid currency code !");
        }
    }

    @Override // com.facebook.hermes.intl.IPlatformNumberFormatter
    public PlatformNumberFormatterICU configure(ILocaleObject<?> iLocaleObject, String str, IPlatformNumberFormatter.Style style, IPlatformNumberFormatter.CurrencySign currencySign, IPlatformNumberFormatter.Notation notation, IPlatformNumberFormatter.CompactDisplay compactDisplay) throws JSRangeErrorException {
        CompactDecimalFormat.CompactStyle compactStyle;
        if (!str.isEmpty()) {
            try {
                if (NumberingSystem.getInstanceByName(JSObjects.getJavaString(str)) == null) {
                    throw new JSRangeErrorException("Invalid numbering system: " + str);
                }
                ArrayList<String> arrayList = new ArrayList<>();
                arrayList.add(JSObjects.getJavaString(str));
                iLocaleObject.setUnicodeExtensions("nu", arrayList);
            } catch (RuntimeException unused) {
                throw new JSRangeErrorException("Invalid numbering system: " + str);
            }
        }
        if (notation == IPlatformNumberFormatter.Notation.COMPACT && (style == IPlatformNumberFormatter.Style.DECIMAL || style == IPlatformNumberFormatter.Style.UNIT)) {
            if (compactDisplay == IPlatformNumberFormatter.CompactDisplay.SHORT) {
                compactStyle = CompactDecimalFormat.CompactStyle.SHORT;
            } else {
                compactStyle = CompactDecimalFormat.CompactStyle.LONG;
            }
            initialize(CompactDecimalFormat.getInstance((ULocale) iLocaleObject.getLocale(), compactStyle), iLocaleObject, style);
        } else {
            android.icu.text.NumberFormat numberFormat = android.icu.text.NumberFormat.getInstance((ULocale) iLocaleObject.getLocale(), style.getInitialNumberFormatStyle(notation, currencySign));
            if (notation == IPlatformNumberFormatter.Notation.ENGINEERING) {
                numberFormat.setMaximumIntegerDigits(3);
            }
            initialize(numberFormat, iLocaleObject, style);
        }
        return this;
    }

    @Override // com.facebook.hermes.intl.IPlatformNumberFormatter
    public String[] getAvailableLocales() {
        ArrayList arrayList = new ArrayList();
        for (ULocale uLocale : ULocale.getAvailableLocales()) {
            arrayList.add(uLocale.toLanguageTag());
        }
        return (String[]) arrayList.toArray(new String[arrayList.size()]);
    }

    @Override // com.facebook.hermes.intl.IPlatformNumberFormatter
    public String getDefaultNumberingSystem(ILocaleObject<?> iLocaleObject) throws JSRangeErrorException {
        return NumberingSystem.getInstance((ULocale) iLocaleObject.getLocale()).getName();
    }
}
