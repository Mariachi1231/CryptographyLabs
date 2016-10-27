using System;
using System.Linq;
using System.Numerics;
using System.Text;
using Cryptography.Algorithm.Math;

namespace Cryptography.Algorithm
{
    public class RSAAlgorithm : CryptoAlgorithmWithAlphabet
    {
        internal static readonly int primeNumbersHighLimit = 10000;
        internal static readonly int primeNumbersLowLimit = 1000;
        internal static readonly int publicExponentLimit = 1000;

        private int[] publicKeys = null;
        private int[] privateKeys = null;

        private int e;

        public RSAAlgorithm(string alphabet)
            : base(alphabet)
        {
        }

        public override string Encrypt(string strToEncryption)
        {
            base.Encrypt(strToEncryption);

            StringBuilder sb = new StringBuilder();

            GenerateKeys();
            var cypher = strToEncryption.Select(x =>
                {
                    if (!alphabet.Contains(x))
                        throw new InvalidOperationException($"{x} isn't contains in alphabet:(");

                    return BigInteger.ModPow(alphabet.IndexOf(x) + 1, publicKeys[0], publicKeys[1]);
                });

            foreach (var number in cypher)
                sb.Append($"{number} ");

            string encryptedStr = sb.ToString();
            return encryptedStr.Substring(0, encryptedStr.Length - 1);
        }

        public override string Decrypt(string strToDecryption)
        {
            base.Decrypt(strToDecryption);

            if (privateKeys == null)
                throw new InvalidOperationException("Invalid privateKeys.");

            StringBuilder sb = new StringBuilder();

            var numbersInStrFormat = strToDecryption.Split(' ');
            foreach (var number in numbersInStrFormat)
            {
                int cypher = int.Parse(number);
                sb.Append(alphabet[(int)BigInteger.ModPow(cypher, privateKeys[0], privateKeys[1])-1]);
            }

            privateKeys = null;
            publicKeys = null;

            return sb.ToString();
        }

        private void GenerateKeys()
        {
            int p = PrimeNumberHelper.GenerateRandomPrime(primeNumbersLowLimit, primeNumbersHighLimit);
            int q = PrimeNumberHelper.GenerateRandomPrime(primeNumbersLowLimit, primeNumbersHighLimit);

            int mod = p * q;
            int eulerFunc = (p - 1) * (q - 1);

            int publicExponent = PrimeNumberHelper.GenerateMutualPrimeNumber(eulerFunc, publicExponentLimit);

            int x, privateExponent;
            EvklidAlgorithm.FindGCDExtended(eulerFunc, publicExponent, out x, out privateExponent);
            if (privateExponent < 0)
                privateExponent += eulerFunc;

            publicKeys = new int[2] { publicExponent, mod };
            privateKeys = new int[2] { privateExponent, mod };
        }
    }
}
