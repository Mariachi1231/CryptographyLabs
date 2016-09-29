using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cryptography.Algorithm.Math
{
    public static class EvklidAlgorithm
    {
        public static int FindGCD(int a, int b)
        {
            int rest = a % b;

            if (rest == 0)
                return b;
            else return FindGCD(b, rest);
        }

        public static int FindGCDExtended(int a, int b, out int x, out int y)
        {
            if (a == 0)
            {
                x = 0;
                y = 1;
                return b;
            }

            int x1, y1;
            int d = FindGCDExtended(b % a, a, out x1, out y1);
            x = y1 - (b / a) * x1;
            y = x1;
            return d;
        }
    }
}