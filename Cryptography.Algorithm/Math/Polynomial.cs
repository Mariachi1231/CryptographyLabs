using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cryptography.Algorithm.Math
{
    public class Polynomial
    {
        private List<PolynomialMember> members;

        public Polynomial()
        {
            members = new List<PolynomialMember>();
        }


        internal Polynomial(List<PolynomialMember> list)
        {
            members = list;
        }

        public Polynomial(params PolynomialMember[] members)
            : this()
        {
            foreach (var member in members)
                Add(member);
        }

        public Polynomial(params double[] values)
            : this()
        {
            int i = values.Count() - 1;
            foreach (var value in values)
            {
                if (value == 0)
                {
                    i--;
                    continue;
                }

                Add(new PolynomialMember(i--, value));
            }

            Clean();
        }

        public PolynomialMember[] Members { get { return members.ToArray(); } }


        private void Add(PolynomialMember pm)
        {
            var member = members.FirstOrDefault(x => x.Power == pm.Power);
            if (member == default(PolynomialMember))
                members.Add(pm);
            else
            {
                members.Remove(member);
                member = member + pm;

                if (member.Value != 0)
                    members.Add(member);
            }

            Clean();
        }


        private void Clean()
        {
            this.members.RemoveAll(x => x.Value == 0);
        }

        internal static Polynomial Add(Polynomial p1, Polynomial p2)
        {
            foreach (var member in p2.Members)
                p1.Add(member);

            return p1;
        }

        internal static Polynomial Substract(Polynomial p1, Polynomial p2)
        {
            foreach (var member in p2.Members)
            {
                member.ViceversaValue();
                p1.Add(member);
            }

            return p1;
        }

        internal static Polynomial Multiply(Polynomial p1, Polynomial p2)
        {
            var polinomial = new Polynomial();
            foreach (var p1Item in p1.members)
                foreach (var p2Item in p2.members)
                    polinomial.Add(p1Item * p2Item);

            polinomial.Clean();
            return polinomial;
        }


        internal static Polynomial DivideWithoutRest(Polynomial p1, Polynomial p2)
        {
            Polynomial result = new Polynomial();
            var maxPowerP2 = p2.Members.Max(x => x.Power);
            do
            {
                var maxPowerP1 = p1.Members.Max(x => x.Power);
                var powerDifference =  maxPowerP1 - maxPowerP2;

                var valueCofficient = p1.Members.First(x => x.Power == maxPowerP1).Value / p2.Members.First(x => x.Power == maxPowerP2).Value;

                var newMember = new PolynomialMember(powerDifference, valueCofficient);

                p1 = p1 - p2 * new Polynomial(newMember);
                p1.Clean();

                if (powerDifference <= 0 && !(p1.Members.Count() == 0))
                    throw new InvalidOperationException("Division with rest isn't supported.");

                result.Add(newMember);
                if (powerDifference == 0)
                    break;

            } while (true);

            return result;
        }

        public static Polynomial operator+(Polynomial left, Polynomial right)
        {
            return Polynomial.Add(left, right);
        }

        public static Polynomial operator-(Polynomial left, Polynomial right)
        {
            return Polynomial.Substract(left, right);
        }

        public static Polynomial operator*(Polynomial left, Polynomial right)
        {
            return Polynomial.Multiply(left, right);
        }
    }
}
