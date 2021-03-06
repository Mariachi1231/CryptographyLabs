﻿using System;
using System.Runtime.InteropServices;
using Cryptography.Algorithm;
using Cryptography.Algorithm.Lab5;
using Cryptography.Algorithm.Lab7;
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
            string message = "fdskdasafdskdasa";

            string encryptedMessage = default(string);
            string decryptedMessage = default(string);

            #region DES algorithm.

            //var service = new CrypthographyService(
            //   new ConsoleMessageWriter(),
            //   new DESAlgorithm("abcdefg"));

            #endregion

            #region RSA algorithm.

            //var service = new CrypthographyService(
            //    new ConsoleMessageWriter(),
            //    new RSAAlgorithm(AlphabetFactory.TakeAlphabet(AlphabetType.Roman)));


            #endregion

            #region Deffi-Helman algorithm.

            //ChannelClient[] clients = new ChannelClient[2]
            //    {
            //        new ChannelClient("client1", new CeasarAlgorithm(AlphabetFactory.TakeAlphabet(AlphabetType.Roman), 0)),
            //        new ChannelClient("client2", new CeasarAlgorithm(AlphabetFactory.TakeAlphabet(AlphabetType.Roman), 0))
            //    };

            //ChannelServiceBase ChannelService = new PeerToPeerChannelService(new ConsoleMessageWriter(), new DiffieHellmanKeyGenerator());
            //ChannelService.AddClient(clients);

            //var message1 = clients[0].SendMessage("hello", true);
            //clients[1].SendMessage($"i can decrypt this shit {clients[1].CryptoAlgorithm.Decrypt(message1)}", false);

            #endregion

            #region Elhamal algorithm.

            //var service = new CrypthographyService(
            //    new ConsoleMessageWriter(),
            //    new ElgamalAlgorithm(AlphabetFactory.TakeAlphabet(AlphabetType.Roman)));

            #endregion

            #region MD5 algorithm.

            //var service = new CrypthographyService(
            //    new ConsoleMessageWriter(),
            //    new MD5Algorithm());

            #endregion

            #region Blowfish algorithm.

            //var service = new CrypthographyService(
            //    new ConsoleMessageWriter(),
            //    new BlowFishAlgorithm("FSDF"));

            #endregion

            #region SHA-1 algorithm.

            //var service = new CrypthographyService(
            //    new ConsoleMessageWriter(),
            //    new SHA1Algorithm());

            #endregion

            #region Cryptography system based on algorithm.

            //var service = new CrypthographyService(
            //    new ConsoleMessageWriter(),
            //    new ElipticCurvesAlgorithm());

            #endregion

            
            var service = new CrypthographyService(
                new ConsoleMessageWriter(),
                new AES128Algorithm("key12345key12345"));

            encryptedMessage = service.CryptoMaster.Encrypt(message);
            decryptedMessage = service.CryptoMaster.Decrypt(encryptedMessage);

            service.MessageWriter.WriteMessage($"Source message: {message}\n Encrypted message: {encryptedMessage}\nDecrypted message: {decryptedMessage}");
        }
    }
}
