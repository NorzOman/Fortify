package com.facebook.hermes.intl;

import androidx.core.text.util.LocalePreferences;
import java.text.AttributedCharacterIterator;

/* loaded from: classes.dex */
public interface IPlatformDateTimeFormatter {
    void configure(ILocaleObject<?> iLocaleObject, String str, String str2, FormatMatcher formatMatcher, WeekDay weekDay, Era era, Year year, Month month, Day day, Hour hour, Minute minute, Second second, TimeZoneName timeZoneName, HourCycle hourCycle, Object obj, DateStyle dateStyle, TimeStyle timeStyle, Object obj2) throws JSRangeErrorException;

    String fieldToString(AttributedCharacterIterator.Attribute attribute, String str);

    String format(double d) throws JSRangeErrorException;

    AttributedCharacterIterator formatToParts(double d) throws JSRangeErrorException;

    String[] getAvailableLocales();

    String getDefaultCalendarName(ILocaleObject<?> iLocaleObject) throws JSRangeErrorException;

    HourCycle getDefaultHourCycle(ILocaleObject<?> iLocaleObject) throws JSRangeErrorException;

    String getDefaultNumberingSystem(ILocaleObject<?> iLocaleObject) throws JSRangeErrorException;

    String getDefaultTimeZone(ILocaleObject<?> iLocaleObject) throws JSRangeErrorException;

    public enum FormatMatcher {
        BESTFIT,
        BASIC;

        @Override // java.lang.Enum
        public String toString() {
            int i = AnonymousClass1.$SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$FormatMatcher[ordinal()];
            if (i == 1) {
                return Constants.LOCALEMATCHER_BESTFIT;
            }
            if (i == 2) {
                return "basic";
            }
            throw new IllegalArgumentException();
        }
    }

    public enum HourCycle {
        H11,
        H12,
        H23,
        H24,
        UNDEFINED;

        @Override // java.lang.Enum
        public String toString() {
            int i = AnonymousClass1.$SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$HourCycle[ordinal()];
            if (i == 1) {
                return LocalePreferences.HourCycle.H11;
            }
            if (i == 2) {
                return LocalePreferences.HourCycle.H12;
            }
            if (i == 3) {
                return LocalePreferences.HourCycle.H23;
            }
            if (i == 4) {
                return LocalePreferences.HourCycle.H24;
            }
            if (i == 5) {
                return "";
            }
            throw new IllegalArgumentException();
        }
    }

    public enum WeekDay {
        LONG,
        SHORT,
        NARROW,
        UNDEFINED;

        @Override // java.lang.Enum
        public String toString() {
            int i = AnonymousClass1.$SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$WeekDay[ordinal()];
            if (i == 1) {
                return "long";
            }
            if (i == 2) {
                return "short";
            }
            if (i == 3) {
                return "narrow";
            }
            if (i == 4) {
                return "";
            }
            throw new IllegalArgumentException();
        }

        public String getSkeleonSymbol() {
            int i = AnonymousClass1.$SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$WeekDay[ordinal()];
            if (i == 1) {
                return "EEEE";
            }
            if (i == 2) {
                return "EEE";
            }
            if (i == 3) {
                return "EEEEE";
            }
            if (i == 4) {
                return "";
            }
            throw new IllegalArgumentException();
        }
    }

    public enum Era {
        LONG,
        SHORT,
        NARROW,
        UNDEFINED;

        @Override // java.lang.Enum
        public String toString() {
            int i = AnonymousClass1.$SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$Era[ordinal()];
            if (i == 1) {
                return "long";
            }
            if (i == 2) {
                return "short";
            }
            if (i == 3) {
                return "narrow";
            }
            if (i == 4) {
                return "";
            }
            throw new IllegalArgumentException();
        }

        public String getSkeleonSymbol() {
            int i = AnonymousClass1.$SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$Era[ordinal()];
            if (i == 1) {
                return "GGGG";
            }
            if (i == 2) {
                return "GGG";
            }
            if (i == 3) {
                return "G5";
            }
            if (i == 4) {
                return "";
            }
            throw new IllegalArgumentException();
        }
    }

    public enum Year {
        NUMERIC,
        DIGIT2,
        UNDEFINED;

        @Override // java.lang.Enum
        public String toString() {
            int i = AnonymousClass1.$SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$Year[ordinal()];
            if (i == 1) {
                return Constants.COLLATION_OPTION_NUMERIC;
            }
            if (i == 2) {
                return "2-digit";
            }
            if (i == 3) {
                return "";
            }
            throw new IllegalArgumentException();
        }

        public String getSkeleonSymbol() {
            int i = AnonymousClass1.$SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$Year[ordinal()];
            if (i == 1) {
                return "yyyy";
            }
            if (i == 2) {
                return "yy";
            }
            if (i == 3) {
                return "";
            }
            throw new IllegalArgumentException();
        }
    }

    public enum Month {
        NUMERIC,
        DIGIT2,
        LONG,
        SHORT,
        NARROW,
        UNDEFINED;

        @Override // java.lang.Enum
        public String toString() {
            switch (AnonymousClass1.$SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$Month[ordinal()]) {
                case 1:
                    return Constants.COLLATION_OPTION_NUMERIC;
                case 2:
                    return "2-digit";
                case 3:
                    return "long";
                case 4:
                    return "short";
                case 5:
                    return "narrow";
                case 6:
                    return "";
                default:
                    throw new IllegalArgumentException();
            }
        }

        public String getSkeleonSymbol() {
            switch (AnonymousClass1.$SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$Month[ordinal()]) {
                case 1:
                    return "M";
                case 2:
                    return "MM";
                case 3:
                    return "MMMM";
                case 4:
                    return "MMM";
                case 5:
                    return "MMMMM";
                case 6:
                    return "";
                default:
                    throw new IllegalArgumentException();
            }
        }
    }

    public enum Day {
        NUMERIC,
        DIGIT2,
        UNDEFINED;

        @Override // java.lang.Enum
        public String toString() {
            int i = AnonymousClass1.$SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$Day[ordinal()];
            if (i == 1) {
                return Constants.COLLATION_OPTION_NUMERIC;
            }
            if (i == 2) {
                return "2-digit";
            }
            if (i == 3) {
                return "";
            }
            throw new IllegalArgumentException();
        }

        public String getSkeleonSymbol() {
            int i = AnonymousClass1.$SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$Day[ordinal()];
            if (i == 1) {
                return "d";
            }
            if (i == 2) {
                return "dd";
            }
            if (i == 3) {
                return "";
            }
            throw new IllegalArgumentException();
        }
    }

    public enum Hour {
        NUMERIC,
        DIGIT2,
        UNDEFINED;

        @Override // java.lang.Enum
        public String toString() {
            int i = AnonymousClass1.$SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$Hour[ordinal()];
            if (i == 1) {
                return Constants.COLLATION_OPTION_NUMERIC;
            }
            if (i == 2) {
                return "2-digit";
            }
            if (i == 3) {
                return "";
            }
            throw new IllegalArgumentException();
        }

        public String getSkeleonSymbol12() {
            int i = AnonymousClass1.$SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$Hour[ordinal()];
            if (i == 1) {
                return "h";
            }
            if (i == 2) {
                return "hh";
            }
            if (i == 3) {
                return "";
            }
            throw new IllegalArgumentException();
        }

        public String getSkeleonSymbol24() {
            int i = AnonymousClass1.$SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$Hour[ordinal()];
            if (i == 1) {
                return "k";
            }
            if (i == 2) {
                return "kk";
            }
            if (i == 3) {
                return "";
            }
            throw new IllegalArgumentException();
        }
    }

    public enum Minute {
        NUMERIC,
        DIGIT2,
        UNDEFINED;

        @Override // java.lang.Enum
        public String toString() {
            int i = AnonymousClass1.$SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$Minute[ordinal()];
            if (i == 1) {
                return Constants.COLLATION_OPTION_NUMERIC;
            }
            if (i == 2) {
                return "2-digit";
            }
            if (i == 3) {
                return "";
            }
            throw new IllegalArgumentException();
        }

        public String getSkeleonSymbol() {
            int i = AnonymousClass1.$SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$Minute[ordinal()];
            if (i == 1) {
                return "m";
            }
            if (i == 2) {
                return "mm";
            }
            if (i == 3) {
                return "";
            }
            throw new IllegalArgumentException();
        }
    }

    public enum Second {
        NUMERIC,
        DIGIT2,
        UNDEFINED;

        @Override // java.lang.Enum
        public String toString() {
            int i = AnonymousClass1.$SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$Second[ordinal()];
            if (i == 1) {
                return Constants.COLLATION_OPTION_NUMERIC;
            }
            if (i == 2) {
                return "2-digit";
            }
            if (i == 3) {
                return "";
            }
            throw new IllegalArgumentException();
        }

        public String getSkeleonSymbol() {
            int i = AnonymousClass1.$SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$Second[ordinal()];
            if (i == 1) {
                return "s";
            }
            if (i == 2) {
                return "ss";
            }
            if (i == 3) {
                return "";
            }
            throw new IllegalArgumentException();
        }
    }

    public enum TimeZoneName {
        LONG,
        LONGOFFSET,
        LONGGENERIC,
        SHORT,
        SHORTOFFSET,
        SHORTGENERIC,
        UNDEFINED;

        @Override // java.lang.Enum
        public String toString() {
            switch (AnonymousClass1.$SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$TimeZoneName[ordinal()]) {
                case 1:
                    return "long";
                case 2:
                    return "longOffset";
                case 3:
                    return "longGeneric";
                case 4:
                    return "short";
                case 5:
                    return "shortOffset";
                case 6:
                    return "shortGeneric";
                case 7:
                    return "";
                default:
                    throw new IllegalArgumentException();
            }
        }

        public String getSkeleonSymbol() {
            switch (AnonymousClass1.$SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$TimeZoneName[ordinal()]) {
                case 1:
                    return "zzzz";
                case 2:
                    return "OOOO";
                case 3:
                    return "vvvv";
                case 4:
                    return "z";
                case 5:
                    return "O";
                case 6:
                    return "v";
                case 7:
                    return "";
                default:
                    throw new IllegalArgumentException();
            }
        }
    }

    public enum DateStyle {
        FULL,
        LONG,
        MEDIUM,
        SHORT,
        UNDEFINED;

        @Override // java.lang.Enum
        public String toString() {
            int i = AnonymousClass1.$SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$DateStyle[ordinal()];
            if (i == 1) {
                return "full";
            }
            if (i == 2) {
                return "long";
            }
            if (i == 3) {
                return "medium";
            }
            if (i == 4) {
                return "short";
            }
            if (i == 5) {
                return "";
            }
            throw new IllegalArgumentException();
        }
    }

    /* renamed from: com.facebook.hermes.intl.IPlatformDateTimeFormatter$1, reason: invalid class name */
    static /* synthetic */ class AnonymousClass1 {
        static final /* synthetic */ int[] $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$DateStyle;
        static final /* synthetic */ int[] $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$Day;
        static final /* synthetic */ int[] $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$Era;
        static final /* synthetic */ int[] $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$FormatMatcher;
        static final /* synthetic */ int[] $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$Hour;
        static final /* synthetic */ int[] $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$HourCycle;
        static final /* synthetic */ int[] $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$Minute;
        static final /* synthetic */ int[] $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$Month;
        static final /* synthetic */ int[] $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$Second;
        static final /* synthetic */ int[] $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$TimeStyle;
        static final /* synthetic */ int[] $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$TimeZoneName;
        static final /* synthetic */ int[] $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$WeekDay;
        static final /* synthetic */ int[] $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$Year;

        static {
            int[] iArr = new int[TimeStyle.values().length];
            $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$TimeStyle = iArr;
            try {
                iArr[TimeStyle.FULL.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$TimeStyle[TimeStyle.LONG.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$TimeStyle[TimeStyle.MEDIUM.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$TimeStyle[TimeStyle.SHORT.ordinal()] = 4;
            } catch (NoSuchFieldError unused4) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$TimeStyle[TimeStyle.UNDEFINED.ordinal()] = 5;
            } catch (NoSuchFieldError unused5) {
            }
            int[] iArr2 = new int[DateStyle.values().length];
            $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$DateStyle = iArr2;
            try {
                iArr2[DateStyle.FULL.ordinal()] = 1;
            } catch (NoSuchFieldError unused6) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$DateStyle[DateStyle.LONG.ordinal()] = 2;
            } catch (NoSuchFieldError unused7) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$DateStyle[DateStyle.MEDIUM.ordinal()] = 3;
            } catch (NoSuchFieldError unused8) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$DateStyle[DateStyle.SHORT.ordinal()] = 4;
            } catch (NoSuchFieldError unused9) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$DateStyle[DateStyle.UNDEFINED.ordinal()] = 5;
            } catch (NoSuchFieldError unused10) {
            }
            int[] iArr3 = new int[TimeZoneName.values().length];
            $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$TimeZoneName = iArr3;
            try {
                iArr3[TimeZoneName.LONG.ordinal()] = 1;
            } catch (NoSuchFieldError unused11) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$TimeZoneName[TimeZoneName.LONGOFFSET.ordinal()] = 2;
            } catch (NoSuchFieldError unused12) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$TimeZoneName[TimeZoneName.LONGGENERIC.ordinal()] = 3;
            } catch (NoSuchFieldError unused13) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$TimeZoneName[TimeZoneName.SHORT.ordinal()] = 4;
            } catch (NoSuchFieldError unused14) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$TimeZoneName[TimeZoneName.SHORTOFFSET.ordinal()] = 5;
            } catch (NoSuchFieldError unused15) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$TimeZoneName[TimeZoneName.SHORTGENERIC.ordinal()] = 6;
            } catch (NoSuchFieldError unused16) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$TimeZoneName[TimeZoneName.UNDEFINED.ordinal()] = 7;
            } catch (NoSuchFieldError unused17) {
            }
            int[] iArr4 = new int[Second.values().length];
            $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$Second = iArr4;
            try {
                iArr4[Second.NUMERIC.ordinal()] = 1;
            } catch (NoSuchFieldError unused18) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$Second[Second.DIGIT2.ordinal()] = 2;
            } catch (NoSuchFieldError unused19) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$Second[Second.UNDEFINED.ordinal()] = 3;
            } catch (NoSuchFieldError unused20) {
            }
            int[] iArr5 = new int[Minute.values().length];
            $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$Minute = iArr5;
            try {
                iArr5[Minute.NUMERIC.ordinal()] = 1;
            } catch (NoSuchFieldError unused21) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$Minute[Minute.DIGIT2.ordinal()] = 2;
            } catch (NoSuchFieldError unused22) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$Minute[Minute.UNDEFINED.ordinal()] = 3;
            } catch (NoSuchFieldError unused23) {
            }
            int[] iArr6 = new int[Hour.values().length];
            $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$Hour = iArr6;
            try {
                iArr6[Hour.NUMERIC.ordinal()] = 1;
            } catch (NoSuchFieldError unused24) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$Hour[Hour.DIGIT2.ordinal()] = 2;
            } catch (NoSuchFieldError unused25) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$Hour[Hour.UNDEFINED.ordinal()] = 3;
            } catch (NoSuchFieldError unused26) {
            }
            int[] iArr7 = new int[Day.values().length];
            $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$Day = iArr7;
            try {
                iArr7[Day.NUMERIC.ordinal()] = 1;
            } catch (NoSuchFieldError unused27) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$Day[Day.DIGIT2.ordinal()] = 2;
            } catch (NoSuchFieldError unused28) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$Day[Day.UNDEFINED.ordinal()] = 3;
            } catch (NoSuchFieldError unused29) {
            }
            int[] iArr8 = new int[Month.values().length];
            $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$Month = iArr8;
            try {
                iArr8[Month.NUMERIC.ordinal()] = 1;
            } catch (NoSuchFieldError unused30) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$Month[Month.DIGIT2.ordinal()] = 2;
            } catch (NoSuchFieldError unused31) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$Month[Month.LONG.ordinal()] = 3;
            } catch (NoSuchFieldError unused32) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$Month[Month.SHORT.ordinal()] = 4;
            } catch (NoSuchFieldError unused33) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$Month[Month.NARROW.ordinal()] = 5;
            } catch (NoSuchFieldError unused34) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$Month[Month.UNDEFINED.ordinal()] = 6;
            } catch (NoSuchFieldError unused35) {
            }
            int[] iArr9 = new int[Year.values().length];
            $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$Year = iArr9;
            try {
                iArr9[Year.NUMERIC.ordinal()] = 1;
            } catch (NoSuchFieldError unused36) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$Year[Year.DIGIT2.ordinal()] = 2;
            } catch (NoSuchFieldError unused37) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$Year[Year.UNDEFINED.ordinal()] = 3;
            } catch (NoSuchFieldError unused38) {
            }
            int[] iArr10 = new int[Era.values().length];
            $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$Era = iArr10;
            try {
                iArr10[Era.LONG.ordinal()] = 1;
            } catch (NoSuchFieldError unused39) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$Era[Era.SHORT.ordinal()] = 2;
            } catch (NoSuchFieldError unused40) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$Era[Era.NARROW.ordinal()] = 3;
            } catch (NoSuchFieldError unused41) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$Era[Era.UNDEFINED.ordinal()] = 4;
            } catch (NoSuchFieldError unused42) {
            }
            int[] iArr11 = new int[WeekDay.values().length];
            $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$WeekDay = iArr11;
            try {
                iArr11[WeekDay.LONG.ordinal()] = 1;
            } catch (NoSuchFieldError unused43) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$WeekDay[WeekDay.SHORT.ordinal()] = 2;
            } catch (NoSuchFieldError unused44) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$WeekDay[WeekDay.NARROW.ordinal()] = 3;
            } catch (NoSuchFieldError unused45) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$WeekDay[WeekDay.UNDEFINED.ordinal()] = 4;
            } catch (NoSuchFieldError unused46) {
            }
            int[] iArr12 = new int[HourCycle.values().length];
            $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$HourCycle = iArr12;
            try {
                iArr12[HourCycle.H11.ordinal()] = 1;
            } catch (NoSuchFieldError unused47) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$HourCycle[HourCycle.H12.ordinal()] = 2;
            } catch (NoSuchFieldError unused48) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$HourCycle[HourCycle.H23.ordinal()] = 3;
            } catch (NoSuchFieldError unused49) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$HourCycle[HourCycle.H24.ordinal()] = 4;
            } catch (NoSuchFieldError unused50) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$HourCycle[HourCycle.UNDEFINED.ordinal()] = 5;
            } catch (NoSuchFieldError unused51) {
            }
            int[] iArr13 = new int[FormatMatcher.values().length];
            $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$FormatMatcher = iArr13;
            try {
                iArr13[FormatMatcher.BESTFIT.ordinal()] = 1;
            } catch (NoSuchFieldError unused52) {
            }
            try {
                $SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$FormatMatcher[FormatMatcher.BASIC.ordinal()] = 2;
            } catch (NoSuchFieldError unused53) {
            }
        }
    }

    public enum TimeStyle {
        FULL,
        LONG,
        MEDIUM,
        SHORT,
        UNDEFINED;

        @Override // java.lang.Enum
        public String toString() {
            int i = AnonymousClass1.$SwitchMap$com$facebook$hermes$intl$IPlatformDateTimeFormatter$TimeStyle[ordinal()];
            if (i == 1) {
                return "full";
            }
            if (i == 2) {
                return "long";
            }
            if (i == 3) {
                return "medium";
            }
            if (i == 4) {
                return "short";
            }
            if (i == 5) {
                return "";
            }
            throw new IllegalArgumentException();
        }
    }
}
