using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Cryptography.Infostructure;

namespace Cryptography.Algorithm
{
    public abstract class CryptoAlgorithm : ICryptoAlgorithm
    {
        public virtual string Decrypt(string strToDecryption)
        {
            if (string.IsNullOrWhiteSpace(strToDecryption))
                throw new ArgumentException("Invalid strToDecryption");

            return strToDecryption;
        }

        public virtual string Encrypt(string strToEncryption)
        {
            if (string.IsNullOrWhiteSpace(strToEncryption))
                throw new ArgumentException("Invalid strToEncryption");

            return strToEncryption;
        }
    }
}
