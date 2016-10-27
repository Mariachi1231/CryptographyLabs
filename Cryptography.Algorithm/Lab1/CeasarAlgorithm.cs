using System;
using System.Linq;

namespace Cryptography.Algorithm
{
    public class CeasarAlgorithm : CryptoAlgorithmWithAlphabetSettableKey
    {
        private int offset;

        internal CeasarAlgorithm(string alphabet)
            : base(alphabet)
        {
        }

        public CeasarAlgorithm(string alphabet, int offset) 
            : base(alphabet)
        {
            if (offset < 0)
                throw new ArgumentException("Invalid offset");

            this.offset = offset;
        }

        internal int Offset { set { this.offset = value; } }

        public override string Encrypt(string strToEncryption)
        {
            base.Encrypt(strToEncryption);

            return new string(strToEncryption.Select(chr => this.Encrypt(chr, this.offset)).ToArray());
        }

        public override void SetKey(string key)
        {
            if (!int.TryParse(key, out offset))
                throw  new ArgumentOutOfRangeException("Invalid format of key.");
        }

        internal char Encrypt(char character, int offset)
        {
            return alphabet.Contains(character) ? alphabet[(alphabet.IndexOf(character) + offset) % alphabet.Count()] : character;
        }

        public override string Decrypt(string strToDecryption)
        {
            base.Decrypt(strToDecryption);

            return new string(strToDecryption.Select(chr => Decrypt(chr, offset)).ToArray());
        }

        internal char Decrypt(char character, int offset)
        {
            if (!alphabet.Contains(character))
                return character;

            int idx = alphabet.IndexOf(character) - (offset % alphabet.Count());
            idx = idx < 0 ? alphabet.Count() - System.Math.Abs(idx) : idx;
            return alphabet[idx];
        }
    }
}
