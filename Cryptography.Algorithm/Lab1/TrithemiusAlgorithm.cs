using System;
using System.Linq;

namespace Cryptography.Algorithm
{
    public class TrithemiusAlgorithm : CryptoAlgorithmWithAlphabet 
    {
        private Func<int, int> offsetFunction;
        private CeasarAlgorithm cesarAlgorithm;

        public TrithemiusAlgorithm(string alphabet, Func<int, int> offsetFunction)
            : base(alphabet)
        {
            if (offsetFunction == null)
                throw new ArgumentNullException("offsetFunction");

            this.offsetFunction = offsetFunction;
            cesarAlgorithm = new CeasarAlgorithm(alphabet);
        }

        public override string Encrypt(string strToEncryption)
        {
            int i = 1;
            return new string(strToEncryption.Select(chr => cesarAlgorithm.Encrypt(chr, offsetFunction(i++))).ToArray());
        }


        public override string Decrypt(string strToDecryption)
        {
            int i = 1;
            return new string(strToDecryption.Select(chr => cesarAlgorithm.Decrypt(chr, offsetFunction(i++))).ToArray());
        }
    }
}
