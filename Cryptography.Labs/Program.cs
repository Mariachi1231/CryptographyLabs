﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Cryptography.Algorithm;
using Cryptography.Infostructure;
using Cryptography.UI;

namespace Cryptography.Labs
{
    class Program
    {
        static void Main(string[] args)
        {
            string message = "ABCD ABRD,EE     F".ToLowerInvariant();

            string encryptedMessage = default(string);
            string decryptedMessage = default(string);

            /* ceasar 
            var service = new CrypthographyService(
                new ConsoleMessageWriter(),
                new CeasarAlgorithm(AlphabetFactory.TakeAlphabet(AlphabetType.Roman), 3));
            */

            /* thrithemiusAlgorithm
            var service = new CrypthographyService(
                new ConsoleMessageWriter(),
                new TrithemiusAlgorithm(AlphabetFactory.TakeAlphabet(AlphabetType.Roman), x => x + 1));
            */

            var service = new CrypthographyService(
                new ConsoleMessageWriter(),
                new GammaAlgorithm(AlphabetFactory.TakeAlphabet(AlphabetType.Roman), "abcd"));

            encryptedMessage = service.CryptoMaster.Encrypt(message);
            decryptedMessage = service.CryptoMaster.Decrypt(encryptedMessage);

            service.MessageWriter.WriteMessage($"Source message: {message}\nEncrypted message: {encryptedMessage}\nDecrypted message: {decryptedMessage}");
        }
    }
}
