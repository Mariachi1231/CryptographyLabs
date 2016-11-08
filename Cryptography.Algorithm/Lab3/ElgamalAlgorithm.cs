using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading;
using Cryptography.Algorithm.Math;

namespace Cryptography.Algorithm
{
    public class ElgamalAlgorithm : CryptoAlgorithmWithAlphabet
    {
        public static readonly int RandomPrimeNumberLowLimit = 10;
        public static readonly int RandomPrimeNumberHighLimit = 500;

        private BigInteger[] publicKey;
        private BigInteger privateKey;

        public ElgamalAlgorithm(string alphabet)
            : base(alphabet)
        {
            GenerateKeys();
        }

        public override string Encrypt(string strToEncryption)
        {
            base.Encrypt(strToEncryption);

            StringBuilder sb = new StringBuilder();

            var letters = strToEncryption.Select(x =>
                {
                    if (!alphabet.Contains(x))
                        throw new InvalidOperationException($"{x} isn't contains in alphabet:(");

                    return alphabet.IndexOf(x) + 1;
                });

            foreach (var letter in letters)
            {
                int sessionKey = GenerateBigInteger(2, (int)publicKey[0] - 1);

                int a = (int) BigInteger.ModPow(publicKey[1], sessionKey,publicKey[0]);
                int b = (int) (BigInteger.Pow(publicKey[2], sessionKey) * letter % publicKey[0]);
                sb.Append($"{a} {b}|");
            }

            return sb.ToString().Substring(0, sb.Length - 1);
        }


        public override string Decrypt(string strToDecryption)
        {
            base.Decrypt(strToDecryption);

            StringBuilder sb = new StringBuilder();
            string[] cyphers = strToDecryption.Split('|');

            List<int[]> cryptoGramms = new List<int[]>();
            foreach (var cypher in cyphers)
            {
                string[] subCyphers = cypher.Split(' ');
                cryptoGramms.Add(new int[] { int.Parse(subCyphers[0]), int.Parse(subCyphers[1]) });
            }

            foreach (var cryptoGramm in cryptoGramms)
            {
                var idx = (int) ((cryptoGramm[1] * BigInteger.Pow(cryptoGramm[0], (int) (publicKey[0] - 1 - privateKey))) % publicKey[0]);
                sb.Append(alphabet[idx - 1]);
            }

            return sb.ToString();
        }

        private void GenerateKeys()
        {
            int p = PrimeNumberHelper.GenerateRandomPrime(RandomPrimeNumberLowLimit, RandomPrimeNumberHighLimit);
            int g = PrimeNumberHelper.PrimitiveRootForPrimeNumber(p);

            Random rand = new Random();
            int x = rand.Next(2, p);
            BigInteger y = BigInteger.ModPow(g, x, p);

            publicKey = new BigInteger[] { p, g, y };
            privateKey = x;
        }

        private int GenerateBigInteger(int lowLimit, int highLimit)
        {
            Random rand = new Random();
            Thread.Sleep(15);

            return rand.Next(lowLimit, highLimit);
        }
    }
}
