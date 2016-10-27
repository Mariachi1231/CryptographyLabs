using Cryptography.Infostructure;

namespace Cryptography.Algorithm
{
    public abstract class CryptoAlgorithmWithAlphabetSettableKey : CryptoAlgorithmWithAlphabet, ICryptoAlgorithmSettableKey
    {
        protected CryptoAlgorithmWithAlphabetSettableKey(string alphabet)
            : base(alphabet)
        {
        }

        public abstract void SetKey(string key);
    }
}