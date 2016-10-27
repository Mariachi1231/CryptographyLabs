using System;
using System.Linq;
using Cryptography.Algorithm.Math;

namespace Cryptography.Algorithm
{
    public class PolinomialAlgorithm : CryptoAlgorithmWithAlphabet
    {
        private Polynomial formativePolynomial;

        public PolinomialAlgorithm(string alphabet, Polynomial formativePolynomial)
            : base(alphabet)
        {
            if (formativePolynomial == null)
                throw new ArgumentNullException("formativePolynomial");

            this.formativePolynomial = formativePolynomial;
        }

        public override string Encrypt(string strToEncryption)
        {
            base.Encrypt(strToEncryption);

            var values = strToEncryption.Select(chr =>
                {
                    if (!alphabet.Contains(chr))
                        throw new ArgumentException($"Invalid string to encryption. Cannot find the character {chr} in assigned alphabet.");

                    return (double) alphabet.IndexOf(chr) + 1;
                }).ToArray();

            var encryptedPolinom = new Polynomial(values) * formativePolynomial;
            return new string(encryptedPolinom.Members.OrderByDescending(x => x.Power).Select(x =>  alphabet[(int) x.Value - 1]).ToArray());
        }

        public override string Decrypt(string strToDecryption)
        {
            base.Decrypt(strToDecryption);

            var values = strToDecryption.Select(chr =>
                {
                    if (!alphabet.Contains(chr))
                        throw new ArgumentException($"Invalid string to decryption. Cannot find the character {chr} in assigned alphabet.");

                    return (double) alphabet.IndexOf(chr) + 1;
                }).ToArray();

            var decryptedPolinom = Polynomial.DivideWithoutRest(new Polynomial(values), formativePolynomial);
            return new string(decryptedPolinom.Members.OrderByDescending(x => x.Power).Select(x => alphabet[(int) x.Value - 1]).ToArray());
        }
    }
}
