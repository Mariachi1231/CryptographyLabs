using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Cryptography.Algorithm;
using Cryptography.Algorithm.Math;
using Cryptography.Infostructure;
using Cryptography.UI;

namespace Cryptography.Labs
{
    class Program
    {
        static void Main(string[] args)
        {
            string path = $"{Environment.CurrentDirectory}\\alphabetPoem.txt";

            //string message = "ABCD ABRD,EE     F".ToLowerInvariant();
            string message = "abc";

            string encryptedMessage = default(string);
            string decryptedMessage = default(string);

            var service = new CrypthographyService(
                new ConsoleMessageWriter(),
                new PolinomialAlgorithm(AlphabetFactory.TakeAlphabet(AlphabetType.Roman), new Polynomial(new double[] { 1, 0, 1, 1 })));

            encryptedMessage = service.CryptoMaster.Encrypt(message);
            decryptedMessage = service.CryptoMaster.Decrypt(encryptedMessage);

            service.MessageWriter.WriteMessage($"Source message: {message}\nEncrypted message: {encryptedMessage}\nDecrypted message: {decryptedMessage}");
        }
    }
}
