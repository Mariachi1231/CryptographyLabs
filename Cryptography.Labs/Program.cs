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
            string message = "abcdefgh";

            string encryptedMessage = default(string);
            string decryptedMessage = default(string);

            // ********** DES *************
            //var service = new CrypthographyService(
            //    new ConsoleMessageWriter(),
            //    new DESAlgorithm("abcdefgh"));


            // ********** RSA *************
            //var service = new CrypthographyService(
            //    new ConsoleMessageWriter(),
            //    new RSAAlgorithm(AlphabetFactory.TakeAlphabet(AlphabetType.Roman)));

            // ********** Diffi-Hellman ************************
            //ChannelClient[] clients = new ChannelClient[2]
            //    {
            //        new ChannelClient("client1", new CeasarAlgorithm(AlphabetFactory.TakeAlphabet(AlphabetType.Roman), 0)),
            //        new ChannelClient("client2", new CeasarAlgorithm(AlphabetFactory.TakeAlphabet(AlphabetType.Roman), 0))
            //    };

            //ChannelServiceBase ChannelService = new PeerToPeerChannelService(new ConsoleMessageWriter(), new DiffieHellmanKeyGenerator());
            //ChannelService.AddClient(clients);

            //var message1 = clients[0].SendMessage("hello", true);
            //clients[1].SendMessage($"i can decrypt this shit {clients[1].CryptoAlgorithm.Decrypt(message1)}", false);

            var service = new CrypthographyService(
                new ConsoleMessageWriter(),
                new ElgamalAlgorithm(AlphabetFactory.TakeAlphabet(AlphabetType.Roman)));

            encryptedMessage = service.CryptoMaster.Encrypt(message);
            decryptedMessage = service.CryptoMaster.Decrypt(encryptedMessage);

            service.MessageWriter.WriteMessage($"Source message: {message}\nEncrypted message: {encryptedMessage}\nDecrypted message: {decryptedMessage}");
        }
    }
}
