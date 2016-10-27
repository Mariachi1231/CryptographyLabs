using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Cryptography.Algorithm.Math;
using Cryptography.Algorithm.Utils;

namespace Cryptography.Algorithm
{
    using static System.Math;

    public class MD5Algorithm : CryptoAlgorithm
    {
        public static readonly int BlockSize = 64;
        public static readonly int DoubleWordSize = 32;
        public static readonly int DataBlockSize = 512;
        public static readonly int PreDataBlockSize = 448;

        public static readonly uint[] DirectionVector = 
            {
                0x67452301, // A
                0xEFCDAB89, // B
                0x98BADCFE, // C
                0x10325476  // D
            };

        private uint[] constTable = null;

        private List<bool> bits;

        public MD5Algorithm()
        {
        }

        public override string Encrypt(string strToEncryption)
        {
            base.Encrypt(strToEncryption);

            bits = strToEncryption.ToByteArray().ToBits().ToList();
            int sourceLength = bits.Count;


            FlowAligment();


            AddMessageLength(sourceLength);

            if (constTable == null)
                InitializeConstTable();

            uint a = DirectionVector[0];
            uint b = DirectionVector[1];
            uint c = DirectionVector[2];
            uint d = DirectionVector[3];

            uint aa = a;
            uint bb = b;
            uint cc = c;
            uint dd = d;

            var dataBlocks = bits.ToChunks(DataBlockSize);
            foreach (var dataBlock in dataBlocks)
            {
                // IT'S REEEEEEEAAAAAL SHIT, DO NOT TRY TO UNDERSTAND IT, JUST USE AND DO NOT TOUCH.
                var word32UnreversedArray = dataBlock.ToChunks(32).ToArray();
                for (int i = 0; i < word32UnreversedArray.Length; i++)
                {
                    IEnumerable<bool> newChunk = new List<bool>();
                    foreach (var smth in word32UnreversedArray[i].ToChunks(8).Reverse())
                        newChunk = newChunk.Concat(smth);

                    word32UnreversedArray[i] = newChunk;
                }
                // SHITS OVER, THANKS FOR ATTENTION.

                var wordArray = word32UnreversedArray.Select(x => x.ConvertFromBinaryToUInt()).ToArray();

                // First stage.
                a = RoundFunction(a, b, c, d, wordArray[0],   7,  1, FuncF);
                d = RoundFunction(d, a, b, c, wordArray[1],  12,  2, FuncF);
                c = RoundFunction(c, d, a, b, wordArray[2],  17,  3, FuncF);
                b = RoundFunction(b, c, d, a, wordArray[3],  22,  4, FuncF);

                a = RoundFunction(a, b, c, d, wordArray[4],   7,  5, FuncF);
                d = RoundFunction(d, a, b, c, wordArray[5],  12,  6, FuncF);
                c = RoundFunction(c, d, a, b, wordArray[6],  17,  7, FuncF);
                b = RoundFunction(b, c, d, a, wordArray[7],  22,  8, FuncF);

                a = RoundFunction(a, b, c, d, wordArray[8],   7,  9, FuncF);
                d = RoundFunction(d, a, b, c, wordArray[9],  12, 10, FuncF);
                c = RoundFunction(c, d, a, b, wordArray[10], 17, 11, FuncF);
                b = RoundFunction(b, c, d, a, wordArray[11], 22, 12, FuncF);

                a = RoundFunction(a, b, c, d, wordArray[12],  7, 13, FuncF);
                d = RoundFunction(d, a, b, c, wordArray[13], 12, 14, FuncF);
                c = RoundFunction(c, d, a, b, wordArray[14], 17, 15, FuncF);
                b = RoundFunction(b, c, d, a, wordArray[15], 22, 16, FuncF);


                // Second stage.
                a = RoundFunction(a, b, c, d, wordArray[1],   5, 17, FuncG);
                d = RoundFunction(d, a, b, c, wordArray[6],   9, 18, FuncG);
                c = RoundFunction(c, d, a, b, wordArray[11], 14, 19, FuncG);
                b = RoundFunction(b, c, d, a, wordArray[0],  20, 20, FuncG);

                a = RoundFunction(a, b, c, d, wordArray[5],   5, 21, FuncG);
                d = RoundFunction(d, a, b, c, wordArray[10],  9, 22, FuncG);
                c = RoundFunction(c, d, a, b, wordArray[15], 14, 23, FuncG);
                b = RoundFunction(b, c, d, a, wordArray[4],  20, 24, FuncG);

                a = RoundFunction(a, b, c, d, wordArray[9],   5, 25, FuncG);
                d = RoundFunction(d, a, b, c, wordArray[14],  9, 26, FuncG);
                c = RoundFunction(c, d, a, b, wordArray[3],  14, 27, FuncG);
                b = RoundFunction(b, c, d, a, wordArray[8],  20, 28, FuncG);

                a = RoundFunction(a, b, c, d, wordArray[13],   5, 29, FuncG);
                d = RoundFunction(d, a, b, c, wordArray[2],  9, 30, FuncG);
                c = RoundFunction(c, d, a, b, wordArray[7],  14, 31, FuncG);
                b = RoundFunction(b, c, d, a, wordArray[12],  20, 32, FuncG);


                // Third stage.
                a = RoundFunction(a, b, c, d, wordArray[5],   4, 33, FuncH);
                d = RoundFunction(d, a, b, c, wordArray[8],  11, 34, FuncH);
                c = RoundFunction(c, d, a, b, wordArray[11], 16, 35, FuncH);
                b = RoundFunction(b, c, d, a, wordArray[14], 23, 36, FuncH);

                a = RoundFunction(a, b, c, d, wordArray[1],   4, 37, FuncH);
                d = RoundFunction(d, a, b, c, wordArray[4],  11, 38, FuncH);
                c = RoundFunction(c, d, a, b, wordArray[7],  16, 39, FuncH);
                b = RoundFunction(b, c, d, a, wordArray[10], 23, 40, FuncH);

                a = RoundFunction(a, b, c, d, wordArray[13],  4, 41, FuncH);
                d = RoundFunction(d, a, b, c, wordArray[0],  11, 42, FuncH);
                c = RoundFunction(c, d, a, b, wordArray[3],  16, 43, FuncH);
                b = RoundFunction(b, c, d, a, wordArray[6],  23, 44, FuncH);

                a = RoundFunction(a, b, c, d, wordArray[9],   4, 45, FuncH);
                d = RoundFunction(d, a, b, c, wordArray[12], 11, 46, FuncH);
                c = RoundFunction(c, d, a, b, wordArray[15], 16, 47, FuncH);
                b = RoundFunction(b, c, d, a, wordArray[2],  23, 48, FuncH);


                // Fourth stage.
                a = RoundFunction(a, b, c, d, wordArray[0],   6, 49, FuncI);
                d = RoundFunction(d, a, b, c, wordArray[7],  10, 50, FuncI);
                c = RoundFunction(c, d, a, b, wordArray[14], 15, 51, FuncI);
                b = RoundFunction(b, c, d, a, wordArray[5],  21, 52, FuncI);

                a = RoundFunction(a, b, c, d, wordArray[12],  6, 53, FuncI);
                d = RoundFunction(d, a, b, c, wordArray[3],  10, 54, FuncI);
                c = RoundFunction(c, d, a, b, wordArray[10], 15, 55, FuncI);
                b = RoundFunction(b, c, d, a, wordArray[1],  21, 56, FuncI);

                a = RoundFunction(a, b, c, d, wordArray[8],   6, 57, FuncI);
                d = RoundFunction(d, a, b, c, wordArray[15], 10, 58, FuncI);
                c = RoundFunction(c, d, a, b, wordArray[6],  15, 59, FuncI);
                b = RoundFunction(b, c, d, a, wordArray[13], 21, 60, FuncI);

                a = RoundFunction(a, b, c, d, wordArray[4],   6, 61, FuncI);
                d = RoundFunction(d, a, b, c, wordArray[11], 10, 62, FuncI);
                c = RoundFunction(c, d, a, b, wordArray[2],  15, 63, FuncI);
                b = RoundFunction(b, c, d, a, wordArray[9],  21, 64, FuncI);

                a += aa;
                b += bb;
                c += cc;
                d += dd;
            }
            
            return CreateOutput(a) + CreateOutput(b) + CreateOutput(c) + CreateOutput(d);
        }

        public override string Decrypt(string strToDecryption)
        {
            throw new InvalidOperationException("This algorithm doesn't support decryption.");
        }

        private void FlowAligment()
        {
            bits.Add(true);

            while (bits.Count % DataBlockSize != PreDataBlockSize)
                bits.Add(false);
        }

        private void AddMessageLength(int sourceLength)
        {
            var lengthBits = sourceLength.ConvertFromIntToBinary().AddWhiteSpaceBits(BlockSize).ToArray();

            var chunks = lengthBits.ToChunks(8).Reverse();
            foreach (var chunk in chunks)
            {
                var array = chunk.ToArray();
                for (int i = 0; i < array.Length; i++)
                    bits.Add(array[i]);
            }
        }

        private void InitializeConstTable()
        {
            constTable = new uint[BlockSize];
            var cnst = Pow(2, 32);
            for (int i = 0; i < BlockSize; i++)
                constTable[i] = (uint) (cnst*Abs(Sin(i+1)));
        }

        private uint FuncF(uint wordX, uint wordY, uint wordZ)
        {
            return (wordX & wordY) | ((~wordX) & wordZ);
        }

        private uint FuncG(uint wordX, uint wordY, uint wordZ)
        {
            return (wordX & wordZ) | ((~wordZ) & wordY);
        }

        private uint FuncH(uint wordX, uint wordY, uint wordZ)
        {
            return wordX ^ wordY ^ wordZ;
        }

        private uint FuncI(uint wordX, uint wordY, uint wordZ)
        {
            return wordY ^ ((~wordZ) | wordX);
        }

        private uint RoundFunction(uint a, uint b, uint c, uint d, uint xk, int s, uint i, Func<uint, uint, uint, uint> func)
        {
            return b + LogicOperations.LeftRotation(a + func(b, c, d) + xk + constTable[i-1], s);
        }

        private string CreateOutput(uint dword)
        {
            StringBuilder sb = new StringBuilder();

            var resultArray = dword.ToString("x").ToChunks(2).Reverse();
            foreach (var item in resultArray)
                sb.Append(new string(item.ToArray()));

            return sb.ToString();
        }
    }
}
