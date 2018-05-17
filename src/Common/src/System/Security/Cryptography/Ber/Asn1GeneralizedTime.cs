// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Text;

namespace System.Security.Cryptography
{
    [Serializable]
    class Asn1GeneralizedTime : Asn1Time
    {
        public static readonly Asn1Tag Tag = new Asn1Tag(0, 0, GeneralTimeTypeCode);

        public Asn1GeneralizedTime()
            : base(GeneralTimeTypeCode, false)
        {
        }

        public Asn1GeneralizedTime(bool useDerRules)
            : base(GeneralTimeTypeCode, useDerRules)
        {
        }

        public Asn1GeneralizedTime(string data)
            : base(data, GeneralTimeTypeCode, false)
        {
        }

        public Asn1GeneralizedTime(string data, bool useDerRules)
            : base(data, GeneralTimeTypeCode, useDerRules)
        {
        }

        public virtual int Century
        {
            get
            {
                var yearValue = Year;

                if (yearValue < 0)
                {
                    throw new Exception("Asn1InvalidYearValue");

                }

                return (yearValue / 100);
            }
            set
            {
                if ((value < 0) || (value > 0x63))
                {
                    throw new Exception("Asn1InvalidCenturyValue");

                }

                SafeParseString();
                YearValue = (value * 100) + (YearValue % 100);
                CompileString();
            }
        }

        protected override bool CompileString()
        {
            int minuteValue;

            if (((YearValue < 0) || (MonthValue <= 0)) || ((DayValue <= 0) || (HourValue < 0)))
            {
                return false;
            }

            Value = "";

            if (StringBuffer == null)
            {
                StringBuffer = new StringBuilder();
            }
            else
            {
                StringBuffer.Length = 0;
            }

            if ((DerRules || UtcFlag) && ((DiffHourValue != 0) || (DiffMinValue != 0)))
            {
                var time = GetTime();
                time.AddMinutes(-DiffMinValue);
                time.AddHours(-DiffHourValue);

                PutInteger(4, time.Year);
                PutInteger(2, time.Month);
                PutInteger(2, time.Day);
                PutInteger(2, time.Hour);

                minuteValue = time.Minute;
            }
            else
            {
                PutInteger(4, YearValue);
                PutInteger(2, MonthValue);
                PutInteger(2, DayValue);
                PutInteger(2, HourValue);

                minuteValue = MinuteValue;
            }

            if ((DerRules || (minuteValue > 0)) || ((SecondValue > 0) || (SecFraction.Length > 0)))
            {
                PutInteger(2, minuteValue);

                if ((DerRules || (SecondValue > 0)) || (SecFraction.Length > 0))
                {
                    PutInteger(2, SecondValue);

                    if (SecFraction.Length > 0)
                    {
                        StringBuffer.Append('.');
                        StringBuffer.Append(SecFraction);
                    }
                }
            }

            if (DerRules || UtcFlag)
            {
                StringBuffer.Append('Z');
            }
            else if ((DiffHourValue != 0) || (DiffMinValue != 0))
            {
                StringBuffer.Append((DiffHourValue > 0) ? '+' : '-');

                if (DiffMinValue != 0)
                {
                    PutInteger(2, Math.Abs(DiffHourValue));
                    PutInteger(2, Math.Abs(DiffMinValue));
                }
                else
                {
                    PutInteger(2, Math.Abs(DiffHourValue));
                }
            }

            Value = StringBuffer.ToString();

            return true;
        }

        public override void Decode(Asn1BerDecodeBuffer buffer, bool explicitTagging, int implicitLength)
        {
            Decode(buffer, explicitTagging, implicitLength, Tag);
        }

        public override int Encode(Asn1BerEncodeBuffer buffer, bool explicitTagging)
        {
            return Encode(buffer, explicitTagging, Tag);
        }

        public override void Encode(Asn1BerOutputStream outs, bool explicitTagging)
        {
            Encode(outs, explicitTagging, Tag);
        }

        public override void ParseString(string data)
        {
            if (data == null)
            {
                throw new Exception("Argument data is Null");
            }

            Clear();

            var off = new IntHolder(0);

            try
            {
                YearValue = ParseInt(data, off, 4);
                MonthValue = ParseInt(data, off, 2);
                DayValue = ParseInt(data, off, 2);

                if (YearValue < 0)
                {
                    throw new Exception("Asn1InvalidYearValue");
                }

                if ((MonthValue < 1) || (MonthValue > 12))
                {
                    throw new Exception("Asn1InvalidMonthValue");
                }

                int num = DaysInMonth[MonthValue];

                if (((MonthValue == 2) && ((YearValue % 4) == 0)) && (((YearValue % 100) != 0) || ((YearValue % 400) == 0)))
                {
                    num++;
                }

                if ((DayValue < 1) || (DayValue > num))
                {
                    throw new Exception("Asn1InvalidDayValue");
                }

                var num2 = 0;

                if (!char.IsDigit(CharAt(data, off.Value)))
                {
                    throw new Exception("Asn1HoursExpected");
                }

                HourValue = ParseInt(data, off, 2);
                num2++;

                if (char.IsDigit(CharAt(data, off.Value)))
                {
                    MinuteValue = ParseInt(data, off, 2);
                    num2++;

                    if (char.IsDigit(CharAt(data, off.Value)))
                    {
                        SecondValue = ParseInt(data, off, 2);
                        num2++;
                    }
                }

                if ((num2 >= 1) && ((HourValue < 0) || (HourValue > 0x17)))
                {
                    throw new Exception("Asn1InvalidHourValue");
                }

                if ((num2 >= 2) && ((MinuteValue < 0) || (MinuteValue > 0x3b)))
                {
                    throw new Exception("Asn1InvalidMinuteValue");
                }

                if ((num2 == 3) && ((SecondValue < 0) || (SecondValue > 0x3b)))
                {
                    throw new Exception("Asn1InvalidSecondValue");
                }

                var ch = CharAt(data, off.Value);

                if (DerRules && (ch == ','))
                {
                    throw new Exception("Asn1InvalidDecimalMark");
                }

                if ((ch == '.') || (ch == ','))
                {
                    off.Value++;

                    if (num2 != 3)
                    {
                        throw new Exception("Asn1UnexpectedSymbol");
                    }

                    var length = 0;

                    while (char.IsDigit(CharAt(data, off.Value + length)))
                    {
                        length++;
                    }

                    if (length == 0)
                    {
                        throw new Exception("Asn1UnexpectedSymbol");
                    }

                    SecFraction = data.Substring(off.Value, length);
                    off.Value += length;
                }

                if (CharAt(data, off.Value) == 'Z')
                {
                    off.Value++;
                    UtcFlag = true;

                    if (off.Value != data.Length)
                    {
                        throw new Exception("Asn1UnexpectedValuesAtEndOfString");
                    }
                }
                else
                {
                    if (DerRules)
                    {
                        throw new Exception("Asn1UnexpectedZoneOffset");
                    }

                    UtcFlag = false;

                    var ch2 = CharAt(data, off.Value);

                    switch (ch2)
                    {
                        case '-':
                        case '+':
                            off.Value++;

                            if (!char.IsDigit(CharAt(data, off.Value)))
                            {
                                throw new Exception("Asn1InvalidDiffHour");
                            }

                            DiffHourValue = ParseInt(data, off, 2);

                            if (char.IsDigit(CharAt(data, off.Value)))
                            {
                                DiffMinValue = ParseInt(data, off, 2);
                            }

                            if ((DiffHourValue < 0) || (DiffHourValue > 12))
                            {
                                throw new Exception("Asn1InvalidDiffHourValue");
                            }

                            if ((DiffMinValue < 0) || (DiffMinValue > 0x3b))
                            {
                                throw new Exception("Asn1InvalidDiffMinuteValue");
                            }

                            if (ch2 == '-')
                            {
                                DiffHourValue = -DiffHourValue;
                                DiffMinValue = -DiffMinValue;
                            }
                            break;
                    }
                }

                Parsed = true;

                if (data != Value)
                {
                    CompileString();
                }
            }
            catch (IndexOutOfRangeException)
            {
                throw new Exception("Asn1InvalidDateFormat");
            }
            catch (FormatException)
            {
                throw new Exception("Asn1InvalidNumberFormat");
            }
            catch (ArgumentException)
            {
                throw new Exception("Asn1InvalidDateFormat");
            }
        }
    }
}
