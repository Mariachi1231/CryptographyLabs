using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Cryptography.Algorithm.Utils;

namespace Cryptography.Algorithm
{
    public class ShtirlitzAlgorithm : CryptoAlgorithmWithAlphabet
    {
        private char[,] alphabetArray;

        public ShtirlitzAlgorithm(string alphabet)
            : base(alphabet)
        {
            int size = ((int) System.Math.Sqrt(alphabet.Length)) + 1;
            alphabetArray = new char[size, size];

            FillAlphabetArray();
        }

        public override string Encrypt(string strToEncryption)
        {
            base.Encrypt(strToEncryption);

            return String.Join(" ", strToEncryption.Select(chr => alphabetArray.IndexOfAll(chr).RandomString()));
        }

        public override string Decrypt(string strToDecryption)
        {
            base.Decrypt(strToDecryption);

            strToDecryption = strToDecryption.Replace(" ", String.Empty);
            StringBuilder sb = new StringBuilder();

            for (int i = 0; i < strToDecryption.Length; i += 4)
                sb.Append(alphabetArray[int.Parse(strToDecryption.Substring(i, 2)), int.Parse(strToDecryption.Substring(i+2, 2))]);

            return sb.ToString();
        }

        private void FillAlphabetArray()
        {
            int i = 0, j = 0;
            alphabet.ToList().ForEach(chr =>
                {
                    if (j == alphabetArray.GetLength(1))
                    {
                       j = 0;
                       i++;
                    }

                    alphabetArray[i, j++] = chr;
                });
        }
    }
}
