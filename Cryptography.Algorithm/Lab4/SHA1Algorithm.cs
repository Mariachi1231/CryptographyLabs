using System;
using System.CodeDom;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Cryptography.Algorithm.Math;
using Cryptography.Algorithm.Utils;
using Microsoft.SqlServer.Server;

namespace Cryptography.Algorithm
{
    public class SHA1Algorithm : CryptoAlgorithm
    {
        public static readonly uint[] H = 
            {
                0x67452301,
                0xEFCDAB89,
                0x98BADCFE,
                0x10325476,
                0xC3D2E1F0
            };

        public static readonly uint[] K =
            {
                0x5A827999,
                0x6ED9EBA1,
                0x8F1BBCDC,
                0xCA62C1D6,
            };

        public static readonly Func<uint, uint, uint, uint>[] F =
        {
            (m, l, k) => (m & l) | (~m & k),
            (m, l, k) =>  m ^ l ^ k,
            (m, l, k) => (m & l) | (m & k) | (l & k),
            (m, l, k) =>  m ^ l ^ k
        }; 

        public override string Encrypt(string strToEncryption)
        {
            List<bool> dataBits = TextPreProcessing(strToEncryption);

            uint A = H[0],
                 B = H[1],
                 C = H[2],
                 D = H[3],
                 E = H[4];

            var dataBlocks = dataBits.ToChunks(512);
            foreach (var dataBlock in dataBlocks)
            {
                var W = dataBlock.ToChunks(32).
                    Select(x => x.ConvertFromBinaryToUInt()).ToList();

                for (int t = 16; t < 80; t++)
                    W.Add(LogicOperations.LeftRotation((W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]), 1));

                uint a = A, 
                     b = B, 
                     c = C, 
                     d = D, 
                     e = E;

                

                for (int t = 0; t < 80; t++)
                {
                    int currentIndex = GetIndex(t);

                    uint temp = LogicOperations.LeftRotation(a, 5) +
                                F[currentIndex].Invoke(b, c, d) + e + K[currentIndex] + W[t];
                    e = d;
                    d = c;
                    c = LogicOperations.LeftRotation(b, 30);
                    b = a;
                    a = temp;

                }

                A += a;
                B += b;
                C += c;
                D += d;
                E += e;

            }

            return A.ToString("X") + B.ToString("X") + C.ToString("X") + D.ToString("X") + E.ToString("X");
        }

        public override string Decrypt(string strToDecryption)
        {
            return string.Empty;
        }

        private List<bool> TextPreProcessing(string str)
        {
            List<bool> dataBits = str.ToByteArray().ToBits().ToList();
            dataBits.Add(true);

            while (dataBits.Count % 512 != 448)
                dataBits.Add(false);

            dataBits.AddRange((str.Length * 8).ConvertFromIntToBinary().AddWhiteSpaceBits(64));
            return dataBits;
        }

        private int GetIndex(int t)
        {
            return t <= 19 ? 0 : 
                   t <= 39 ? 1 :
                   t <= 59 ? 2 :
                   t <= 79 ? 3 : -1;
        }
    }
}