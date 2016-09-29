using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Cryptography.Algorithm.Utils;
using Cryptography.Algorithm.Enums;
using System.Diagnostics;


// TODO REFACT
namespace Cryptography.Algorithm
{
    public class DESAlgorithm : CryptoAlgorithm
    {
        public const int byteSizeInBits = 8;
        public const int blockSizeInBytes = 8;
        public const int blockSizeInBits = 64;

        public const int roundsAmount = 16;

        public static readonly int[] ipTable = { 58, 50, 42, 34, 26, 18, 10, 2,
                                                 60, 52, 44, 36, 28, 20, 12, 4,
                                                 62, 54, 46, 38, 30, 22, 14, 6,
                                                 64, 56, 48, 40, 32, 24, 16, 8,
                                                 57, 49, 41, 33, 25, 17, 9,  1,
                                                 59, 51, 43, 35, 27, 19, 11, 3,
                                                 61, 53, 45, 37, 29, 21, 13, 5,
                                                 63, 55, 47, 39, 31, 23, 15, 7 };

        public static readonly int[] inverseIpTable = { 40, 8, 48, 16, 56, 24, 64, 32,
                                                        39, 7, 47, 15, 55, 23, 63, 31,
                                                        38, 6, 46, 14, 54, 22, 62, 30,
                                                        37, 5, 45, 13, 53, 21, 61, 29,
                                                        36, 4, 44, 12, 52, 20, 60, 28,
                                                        35, 3, 43, 11, 51, 19, 59, 27,
                                                        34, 2, 42, 10, 50, 18, 58, 26,
                                                        33, 1, 41, 9,  49, 17, 57, 25 };

        public static readonly int[] pExtensionBox = { 32, 1,  2,  3,  4,  5,
                                                       4,  5,  6,  7,  8,  9,
                                                       8,  9,  10, 11, 12, 13,
                                                       12, 13, 14, 15, 16, 17,
                                                       16, 17, 18, 19, 20, 21,
                                                       20, 21, 22, 23, 24, 25,
                                                       24, 25, 26, 27, 28, 29,
                                                       28, 29, 30, 31, 32, 1  };

        public static readonly int[] removeCheckBitsTable = { 57, 49, 41, 33, 25, 17, 9,  1,
                                                              58, 50, 42, 34, 26, 18, 10, 2,
                                                              59, 51, 43, 35, 27, 19, 11, 3,
                                                              60, 52, 44, 36, 63, 55, 47, 39,
                                                              31, 23, 15, 7 , 62, 54, 46, 38,
                                                              30, 22, 14, 6 , 61, 53, 45, 37,
                                                              29, 21, 13, 5 , 28, 20, 12, 4  };

        public static readonly int[][] offsetTables = {
                                                        new int[] {  1,  1,  2,  2,  2,  2,  2,  2,  1,  2,  2,  2,  2,  2,  2,  1, },
                                                        new int[] {  0, -1, -2, -2, -2, -2, -2, -2, -1, -2, -2, -2, -2, -2, -2, -1  }
                                                   };

        public static readonly int[] pKeyCompressionBox = { 14, 17, 11, 24, 1,  5,  3, 28,
                                                            15, 6,  21, 10, 23, 19, 12, 4,
                                                            26, 8,  16, 7,  27, 20, 13, 2,
                                                            41, 52, 31, 37, 47, 55, 30, 40,
                                                            51, 45, 33, 48, 44, 49, 39, 56,
                                                            34, 53, 46, 42, 50, 36, 29, 32 };

        public static readonly int[][,] sBoxes = new int[8][,]
            {
                new int[,]
                { 
                    { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
                    { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
                    { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
                    { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 }
                },
                new int[,]
                {
                    { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
                    { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
                    { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
                    { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 }
                },
                new int[,]
                {
                    { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
                    { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
                    { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
                    { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 }
                },
                new int[,]
                {
                    { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
                    { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
                    { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
                    { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 }
                },
                new int[,]
                {
                    { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
                    { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
                    { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
                    { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 }
                },
                new int[,]
                {
                    { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
                    { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
                    { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
                    { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 }
                },
                new int[,]
                {
                    { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
                    { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
                    { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
                    { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 }
                },
                new int[,]
                { 
                    { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
                    { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
                    { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
                    { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 }
                }
            };

        public static readonly int[] pStraightForwardBox = { 16, 7, 20, 21, 29, 12, 28, 17,
                                                             1, 15, 23, 26, 5,  18, 31, 10,
                                                             2,  8, 24, 14, 32, 27, 3,  9,
                                                             19, 13, 30, 6, 22, 11, 4,  25, };

        private string key;
        private IEnumerable<bool> keyBits;

        private DESAlgorithm()
        {

        }

        public DESAlgorithm(string key)
        {
            if (!Is64bitMult(key))
                throw new ArgumentException("Invalid size of key. DES algorithm requires 64bit key.");

            this.key = key;
            this.keyBits = null;
        }

        internal string Key
        {
            get { return this.key; }
            set
            {
                this.key = value;
                keyBits = null;
            }
        }


        public override string Encrypt(string strToEncryption)
        {
            base.Encrypt(strToEncryption);

            if (!Is64bitMult(strToEncryption))
                strToEncryption = AddHiddenInformation(strToEncryption);

            var bytes = strToEncryption.ToByteArray();
            IEnumerable<IEnumerable<byte>> byteChuncks = bytes.ToChunks(blockSizeInBytes);

            if (keyBits == null)
            {
                var keyBytes = key.ToByteArray();
                keyBits = keyBytes.ToBits();
            }

            string result = String.Empty;
            foreach (var chunk in byteChuncks)
                result = String.Concat(result, EncryptByDESStep(chunk));

            return result;
        }

        public override string Decrypt(string strToDecryption)
        {
            base.Decrypt(strToDecryption);

            if (!Is64bitMult(strToDecryption))
                throw new ArgumentException("Invalid string to decryption");

            var bytes = strToDecryption.ToByteArray();
            IEnumerable<IEnumerable<byte>> byteChuncks = bytes.ToChunks(blockSizeInBytes);

            if (keyBits == null)
            {
                var keyBytes = key.ToByteArray();
                keyBits = keyBytes.ToBits();
            }

            string result = String.Empty;
            foreach (var chunk in byteChuncks)
                result = String.Concat(result, DecryptByDESStep(chunk));

            return result;
        }

        private string EncryptByDESStep(IEnumerable<byte> bytes)
        {
            if (bytes.Count() != blockSizeInBytes)
                throw new ArgumentException($"Invalid size of bytes array. DES works only with {blockSizeInBytes}byte blocks");

            var bits = bytes.ToBits();

            bits = PermutationByTable(bits, ipTable);

            IEnumerable<bool> left, right;
            bits.DivideIntoTwoParts(out left, out right);

            var keyBitsSequence = PermutationByTable(keyBits, removeCheckBitsTable);

            IEnumerable<bool> afterRoundsSequence = null;
            for (int i = 0; i < roundsAmount; i++)
            {
                var rightExtended = PermutationByTable(right, pExtensionBox);

                keyBitsSequence = CreatePreRoundKey(keyBitsSequence, i, CryptoStrategy.Encryption);

                var roundKey = PermutationByTable(keyBitsSequence, pKeyCompressionBox) as bool[];

                var newRight = new List<bool>();
                int j = 0;
                foreach (var item in rightExtended)
                    newRight.Add(item ^ roundKey[j++]);
              
                var vectors = newRight.ToChunks(6);
                newRight = new List<bool>();

                int k = 0;
                foreach (var vector in vectors)
                {
                    var vectorArray = vector.ToArray();
                    var row = new bool[] { vectorArray[0], vectorArray[5] };
                    var column = new bool[] { vectorArray[1], vectorArray[2], vectorArray[3], vectorArray[4] };

                    int newVector = sBoxes[k++][row.ConvertFromBinaryToInt(), column.ConvertFromBinaryToInt()];


                    var vectorInBitFormat = newVector.ConvertFromIntToBinary().AddWhiteSpace(4);
                    newRight.AddRange(vectorInBitFormat);
                }

                var f = PermutationByTable(newRight, pStraightForwardBox);
                newRight = new List<bool>();

                var fArray = f.ToArray();
                k = 0;
                foreach (var item in left)
                    newRight.Add(item ^ fArray[k++]);

                    
                left = right;
                right = newRight;

                if (i == roundsAmount - 1)
                    afterRoundsSequence = left.Concat(right);
            }

            return PermutationByTable(afterRoundsSequence, inverseIpTable).ToBytes().GetStringEquation();
        }

        private string DecryptByDESStep(IEnumerable<byte> bytes)
        {
            if (bytes.Count() != blockSizeInBytes)
                throw new ArgumentException($"Invalid size of bytes array. DES works only with {blockSizeInBytes}byte blocks");

            var bits = bytes.ToBits();

            bits = PermutationByTable(bits, ipTable);

            IEnumerable<bool> left, right;
            bits.DivideIntoTwoParts(out left, out right);

            var keyBitsSequence = PermutationByTable(keyBits, removeCheckBitsTable);

            IEnumerable<bool> afterRoundsSequence = null;
            for (int i = roundsAmount - 1; i >= 0; i--)
            {
                var leftExtended = PermutationByTable(left, pExtensionBox);

                keyBitsSequence = CreatePreRoundKey(keyBitsSequence, roundsAmount - 1 - i, CryptoStrategy.Decryption);

                Debug.WriteLine($"decryption round{i} key: {keyBitsSequence.StringInvariant()}");

                var roundKey = PermutationByTable(keyBitsSequence, pKeyCompressionBox) as bool[];

                var newleft = new List<bool>();
                int j = 0;
                foreach (var item in leftExtended)
                    newleft.Add(item ^ roundKey[j++]);

                var vectors = newleft.ToChunks(6);
                newleft = new List<bool>();

                int k = 0;
                foreach (var vector in vectors)
                {
                    var vectorArray = vector.ToArray();
                    var row = new bool[] { vectorArray[0], vectorArray[5] };
                    var column = new bool[] { vectorArray[1], vectorArray[2], vectorArray[3], vectorArray[4] };

                    int newVector = sBoxes[k++][row.ConvertFromBinaryToInt(), column.ConvertFromBinaryToInt()];


                    var vectorInBitFormat = newVector.ConvertFromIntToBinary().AddWhiteSpace(4);
                    newleft.AddRange(vectorInBitFormat);
                }

                var f = PermutationByTable(newleft, pStraightForwardBox);
                newleft = new List<bool>();

                var fArray = f.ToArray();
                k = 0;
                foreach (var item in right)
                    newleft.Add(item ^ fArray[k++]);

                right = left;
                left = newleft;

                if (i == 0)
                    afterRoundsSequence = left.Concat(right);
            }

            return PermutationByTable(afterRoundsSequence, inverseIpTable).ToBytes().GetStringEquation();
        }

        private bool Is64bitMult(string strToEncryption)
        {
            return strToEncryption.Length % blockSizeInBytes == 0;
        }

        private string AddHiddenInformation(string strToEncryption)
        {
            StringBuilder sb = new StringBuilder(strToEncryption);
            int lack = blockSizeInBytes - (strToEncryption.Length % blockSizeInBytes);
            for (int i = 0; i < lack; i++)
                sb.Append(" ");

            return sb.ToString();
        }

        private IEnumerable<bool> CreatePreRoundKey(IEnumerable<bool> keyBitsSequence, int round, CryptoStrategy cryptoStrategy)
        {
            int roundOffset = offsetTables[(int) cryptoStrategy][round];

            IEnumerable<bool> C, D;
            keyBitsSequence.DivideIntoTwoParts(out C, out D);

            var CArray = C.ToArray();
            var DArray = D.ToArray();

            CArray = ShiftKey(CArray, roundOffset);
            DArray = ShiftKey(DArray, roundOffset);

            return CArray.Concat(DArray);
        }

        private bool[] ShiftKey(bool[] key, int offset)
        {
            bool[] result = new bool[key.Length];
            for (int i = 0; i < key.Length; i++)
            {
                if (i + offset + 1 > key.Length)
                    result[i] = key[i + offset - key.Length];
                else if (i + offset < 0)
                    result[i] = key[key.Length + i + offset];
                else
                    result[i] = key[i + offset];
            }

            return result;
        }

        private IEnumerable<bool> PermutationByTable(IEnumerable<bool> bits, int[] table)
        {
            var bitsArray = bits.ToArray();
            bool[] newBitsSequence = new bool[table.Length];
            for (int i = 0; i < newBitsSequence.Length; i++)
                newBitsSequence[i] = bitsArray[table[i] - 1];

            return newBitsSequence;
        }

    }
}
