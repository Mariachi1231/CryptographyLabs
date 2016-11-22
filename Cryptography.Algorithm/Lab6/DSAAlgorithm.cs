using Cryptography.Algorithm.Utils;

namespace Cryptography.Algorithm.Lab6
{
    public class DSAAlgorithm : CryptoAlgorithm
    {
        private readonly uint sequenceSize = 160;

        public DSAAlgorithm()
        {
            
        }

        public override string Encrypt(string strToEncryption)
        {
            return base.Encrypt(strToEncryption);
        }

        public override string Decrypt(string strToDecryption)
        {
            return base.Decrypt(strToDecryption);
        }

        private void Initialize()
        {
            
        }

        private void GenerateQ()
        {

        }
    }
}