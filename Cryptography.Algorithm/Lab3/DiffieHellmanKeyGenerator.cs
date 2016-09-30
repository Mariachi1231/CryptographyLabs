using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Cryptography.Infostructure;
using Cryptography.Algorithm.Math;
using System.Threading;
using System.Numerics;

namespace Cryptography.Algorithm
{
    public class DiffieHellmanKeyGenerator : IKeyGenerator
    {
        public static readonly int randomPrimeNumberLowLimit  = 10000;
        public static readonly int randomPrimeNumberHighLimit = 100000;

        private int g, n;

        public DiffieHellmanKeyGenerator()
        {
            g = PrimeNumberHelper.GenerateRandomPrime(randomPrimeNumberLowLimit, randomPrimeNumberHighLimit);
            n = PrimeNumberHelper.GenerateRandomPrime(randomPrimeNumberLowLimit, randomPrimeNumberHighLimit);
        }

        public string GenerateAdditionalInformation(string secret)
        {
            int secretNumber = int.Parse(secret);
            return BigInteger.ModPow(g, secretNumber, n).ToString();
        }

        public string GenerateKey(string additionalInformation, string secret)
        {
            int additionalNumber = int.Parse(additionalInformation);
            int secretNumber = int.Parse(secret);
            return BigInteger.ModPow(additionalNumber, secretNumber, n).ToString();
        }
    }
}
