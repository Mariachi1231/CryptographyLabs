﻿using System;
using System.Linq;

namespace Cryptography.Algorithm
{
    public class GammaAlgorithm : CryptoAlgorithmWithAlphabetSettableKey
    {
        private string gamma;
        public GammaAlgorithm(string alphabet, string gamma)
            : base(alphabet)
        {
            if (string.IsNullOrWhiteSpace(gamma))
                throw new ArgumentException("Invalid gamma");

            this.gamma = gamma;
        }

        public override string Encrypt(string strToEncryption)
        {
            base.Encrypt(strToEncryption);

            int i = 0;
            return new string(strToEncryption.Select(chr =>
                {
                    if (!alphabet.Contains(chr))
                        return chr;

                    if (i == gamma.Count())
                        i = 0;

                    if (!alphabet.Contains(gamma[i]))
                        throw new ArgumentException($"Invalid gamma. Alphabet doesn't contain the character {gamma[i]} from gamma");

                    return alphabet[(alphabet.IndexOf(chr) + alphabet.IndexOf(gamma[i++])) % alphabet.Count()];
                }).ToArray());
        }

        public override void SetKey(string key)
        {
            if (string.IsNullOrWhiteSpace(key))
                throw  new ArgumentNullException("key");

            gamma = key;
        }

        public override string Decrypt(string strToDecryption)
        {
            base.Decrypt(strToDecryption);

            int i = 0;
            return new string(strToDecryption.Select(chr =>
                {
                    if (!alphabet.Contains(chr))
                        return chr;

                    if (i == gamma.Count())
                        i = 0;

                    if (!alphabet.Contains(gamma[i]))
                        throw new ArgumentException($"Invalid gamma. Alphabet doesn't contain the character {gamma[i]} from gamma");

                    int offset = alphabet.IndexOf(chr) - alphabet.IndexOf(gamma[i++]);
                    return offset < 0 ? alphabet[alphabet.Count() - System.Math.Abs(offset)] : alphabet[offset];
                }).ToArray());
        }
    }
}
