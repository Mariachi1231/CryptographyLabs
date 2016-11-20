using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Cryptography.Algorithm.Math
{
    internal static class PrimeNumberHelper
    {
        internal static List<int> primesCache;

        internal static int GenerateRandomPrime(int lowLimit, int highLimit)
        {
            if (lowLimit > highLimit || lowLimit < 0 || highLimit < 0)
                throw new ArgumentException("Invalid ranges.");

            if (primesCache == null)
                (primesCache = new List<int>()).Add(2);

            Random rand = new Random();

            int last = primesCache.Last();
            bool isSimple = false;
            for (int i = last == 2 ? last + 1 : last; i < highLimit; i += 2)
            {
                isSimple = true;
                foreach (var prime in primesCache)
                {
                    if (prime * prime - 1 > i)
                    {
                        primesCache.Add(i);
                        isSimple = false;
                        break;
                    }

                    if (i % prime == 0)
                    {
                        isSimple = false;
                        break;
                    }
                }

                if (isSimple)
                    primesCache.Add(i);
            }

            var primesWithLimit = primesCache.Where(x => x > lowLimit);
            return primesWithLimit.ElementAt(rand.Next(primesWithLimit.Count()));
        }

        internal static int GenerateMutualPrimeNumber(int number, int limit)
        {
            Random rand = new Random();
            List<int> mutualPrime = new List<int>();
            for (int i = 1; i < limit; i++)
                if (EvklidAlgorithm.FindGCD(number, i) == 1)
                    mutualPrime.Add(i);

            return mutualPrime.ElementAt(rand.Next(mutualPrime.Count));
        }

        internal static int PrimitiveRootForPrimeNumber(int primeNumber)
        {
            List<int> fact = new List<int>();

            int eulerFunc = EulerFuncForPrime(primeNumber);
            int n = eulerFunc;

            for (int i = 2; i * i < n; i++)
            {
                if (n % i == 0)
                {
                    fact.Add(i);
                    while (n % i == 0)
                        n /= i;
                }
            }

            if (n > 1)
                fact.Add(n);

            var factArray = fact.ToArray();
            for (int res = 2; res <= primeNumber; res++)
            {
                bool ok = true;
                for (int i = 0; i < factArray.Length && ok; i++)
                    ok &= System.Numerics.BigInteger.ModPow(res, eulerFunc / factArray[i], primeNumber) != 1;
                if (ok)
                    return res;
            }

            return -1;
        }

        internal static int EulerFuncForPrime(int primeNumber)
        {
            return primeNumber - 1;
        }
    }
}
