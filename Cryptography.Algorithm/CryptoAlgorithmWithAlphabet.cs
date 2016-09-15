using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cryptography.Algorithm
{
    // TODO     Remove hard coupling.
    public class CryptoAlgorithmWithAlphabet : CryptoAlgorithm
    {
        protected readonly string alphabet;

        private CryptoAlgorithmWithAlphabet()
        {
        }

        public CryptoAlgorithmWithAlphabet(string alphabet)
        {
            if (string.IsNullOrEmpty(alphabet))
                throw new ArgumentException("Invalid alphabet");

            this.alphabet = alphabet;
        }
    }
}
