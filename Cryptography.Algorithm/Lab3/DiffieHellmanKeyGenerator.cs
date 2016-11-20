using System.Numerics;
using Cryptography.Algorithm.Math;
using Cryptography.Infostructure;

namespace Cryptography.Algorithm
{
    public class DiffieHellmanKeyGenerator : IKeyGenerator
    {
        public static readonly int RandomPrimeNumberLowLimit  = 10000;
        public static readonly int RandomPrimeNumberHighLimit = 100000;

        private int g, n;

        public DiffieHellmanKeyGenerator()
        {
            g = PrimeNumberHelper.GenerateRandomPrime(RandomPrimeNumberLowLimit, RandomPrimeNumberHighLimit);
            n = PrimeNumberHelper.GenerateRandomPrime(RandomPrimeNumberLowLimit, RandomPrimeNumberHighLimit);
        }

        public string GenerateAdditionalInformation(string secret)
        {
            int secretNumber = int.Parse(secret);
            return System.Numerics.BigInteger.ModPow(g, secretNumber, n).ToString();
        }

        public string GenerateKey(string additionalInformation, string secret)
        {
            int additionalNumber = int.Parse(additionalInformation);
            int secretNumber = int.Parse(secret);
            return System.Numerics.BigInteger.ModPow(additionalNumber, secretNumber, n).ToString();
        }
    }
}
