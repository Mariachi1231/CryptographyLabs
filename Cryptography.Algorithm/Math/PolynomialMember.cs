using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cryptography.Algorithm.Math
{
    public struct PolynomialMember
    {
        private double power;
        private double value;

        public PolynomialMember(double power, double value)
        {
            this.power = power;
            this.value = value;
        }

        public double Power { get { return this.power; } }

        public double Value { get { return this.value; } }

        internal void ViceversaValue()
        {
            value = -value;
        }

        public override bool Equals(object obj)
        {
            if (typeof(PolynomialMember).Equals(obj.GetType()))
            {
                if (base.Equals(obj))
                    return true;

                PolynomialMember comp = (PolynomialMember) obj;
                if (this.Power == comp.Power && this.Value == comp.Value)
                    return true;
            }

            return false;
        }

        public override int GetHashCode()
        {
            return (int) this.value ^ (int) this.power;
        }

        internal static PolynomialMember Multiply(PolynomialMember p1, PolynomialMember p2)
        {
            return new PolynomialMember(p1.power + p2.power, p1.value * p2.value);
        }

        internal static PolynomialMember Divide(PolynomialMember p1, PolynomialMember p2)
        {
            return new PolynomialMember(p1.power - p2.power, p1.value / p2.value);
        }

        internal static PolynomialMember Add(PolynomialMember p1, PolynomialMember p2)
        {
            if (p1.power == p2.power)
                return new PolynomialMember(p1.power, p1.value + p2.value);
            else throw new InvalidOperationException("Cannot add polynomialMember with different powers.");
        }

        internal static PolynomialMember Substract(PolynomialMember p1, PolynomialMember p2)
        {
            if (p1.power == p2.power)
                return new PolynomialMember(p1.power, p1.value - p2.value);
            else throw new InvalidOperationException("Cannot substract polynomialMember with different powers.");
        }

        public static PolynomialMember operator*(PolynomialMember left, PolynomialMember right)
        {
            return PolynomialMember.Multiply(left, right);
        }

        public static PolynomialMember operator/(PolynomialMember left, PolynomialMember right)
        {
            return PolynomialMember.Divide(left, right);
        }

        public static PolynomialMember operator+(PolynomialMember left, PolynomialMember right)
        {
            return PolynomialMember.Add(left, right);
        }

        public static PolynomialMember operator-(PolynomialMember left, PolynomialMember right)
        {
            return PolynomialMember.Substract(left, right);
        }

        public static bool operator==(PolynomialMember left, PolynomialMember right)
        {
            return PolynomialMember.Equals(left, right);
        }

        public static bool operator!=(PolynomialMember left, PolynomialMember right)
        {
            return !PolynomialMember.Equals(left, right);
        }
    }
}
