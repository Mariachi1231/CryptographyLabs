using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Resources;
using System.Security.Cryptography;
using System.Text;
using Cryptography.Algorithm.Utils;

namespace Cryptography.Algorithm.Lab7
{
    public class AES128Algorithm : CryptoAlgorithm
    {
        private static readonly int keySize = 128;
        private static readonly int inputStateSize = 128;

        private static readonly int countBlockRows = 4;
        private static readonly int Nb = 4;
        private static readonly int Nk = 4;
        private static readonly int Nr = 10;

        private static readonly byte[,] state;

        private static readonly byte[] sBox =
        {
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
        };

        private static readonly byte[] InvertSBox =
        {
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
            0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
            0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
            0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
            0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
            0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
            0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
            0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
            0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
            0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
            0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
            0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
            0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
            0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
        };

        private static readonly byte[][] Rcon =
        {
            new byte[] {0x00, 0x00, 0x00, 0x00},
            new byte[] {0x01, 0x00, 0x00, 0x00},
            new byte[] {0x02, 0x00, 0x00, 0x00},
            new byte[] {0x04, 0x00, 0x00, 0x00},
            new byte[] {0x08, 0x00, 0x00, 0x00},
            new byte[] {0x10, 0x00, 0x00, 0x00},
            new byte[] {0x20, 0x00, 0x00, 0x00},
            new byte[] {0x40, 0x00, 0x00, 0x00},
            new byte[] {0x80, 0x00, 0x00, 0x00},
            new byte[] {0x1b, 0x00, 0x00, 0x00},
            new byte[] {0x36, 0x00, 0x00, 0x00}
        };

        static AES128Algorithm()
        {
            state = new byte[countBlockRows, Nb];   
        }


        private byte[,] cypherKey;
        private byte[,] roundKeys;

        public AES128Algorithm(string key)
        {
            if (!AlgorithmUtils.IsCanDivideByBits(key, keySize))
                throw new ArgumentOutOfRangeException("Invalid size of key. AES-128 requires 128 bit key.");

            var keyBytes = Encoding.ASCII.GetBytes(key);
            FeelKey(keyBytes);
            KeyExpansion();
        }


        public override string Encrypt(string strToEncryption)
        {
            if (!AlgorithmUtils.IsCanDivideByBits(strToEncryption, inputStateSize))
                strToEncryption = AlgorithmUtils.AddHiddenInformation(strToEncryption, inputStateSize);

            var bytes = Encoding.ASCII.GetBytes(strToEncryption);

            IEnumerable<IEnumerable<byte>> byteChuncks = bytes.ToChunks(inputStateSize / 8);

            string result = "";
            foreach (var inputChunk in byteChuncks)
            {
                var inputArray = inputChunk.ToArray();

                CopyInputToState(inputArray);
                AddRoundKey(0);

                for (int round = 1; round < Nr - 1; round++)
                {
                    SubBytes();
                    ShiftRows();
                    MixColumns();
                    AddRoundKey(round);
                }

                SubBytes();
                ShiftRows();
                AddRoundKey(Nr);
                result += CopyStateToOut();
            }

            return result;
        }

        public override string Decrypt(string strToDecryption)
        {
            var bytes = Encoding.ASCII.GetBytes(strToDecryption);

            IEnumerable<IEnumerable<byte>> byteChuncks = bytes.ToChunks(inputStateSize / 8);

            string result = "";
            foreach (var inputChunk in byteChuncks)
            {
                var inputArray = inputChunk.ToArray();

                CopyInputToState(inputArray);
                AddRoundKey(Nr);

                for (int round = Nr - 1; round > 0; round--)
                {
                    InvertShifRows();
                    InvertSubBytes();
                    AddRoundKey(round);
                    InvertMixColumns();
                }

                InvertShifRows();
                InvertSubBytes();
                AddRoundKey(0);
                result += CopyStateToOut();
            }

            return result;

        }

        private void CopyInputToState(byte[] input)
        {
            for (int i = 0; i < state.GetLength(0); i++)
                for (int j = 0; j < state.GetLength(1); j++)
                    state[j, i] = input[i * 4 + j];
        }

        private string CopyStateToOut()
        {
            byte[] output = new byte[4 * 4];
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    output[i * 4 + j] = state[j, i];

            return Encoding.ASCII.GetString(output);
        }

        private void FeelKey(byte[] bytes)
        {
            cypherKey = new byte[countBlockRows, Nk];
            for (int i = 0; i < cypherKey.GetLength(0); i++)
                for (int j = 0; j < cypherKey.GetLength(1); j++)
                    cypherKey[i, j] = bytes[cypherKey.GetLength(0)*i + j];
        }

        private void KeyExpansion()
        {
            roundKeys = new byte[(Nr + 1) * Nk, 4];

            byte[] tempWord = new byte[4];

            for (int i = 0; i < Nk; i++)
                for (int j = 0; j < 4; j++)
                    roundKeys[i, j] = cypherKey[i, j];

            for (int i = Nk; i < (Nr + 1) * Nk; i++)
            {
                for (int j = 0; j < 4; j++)
                    tempWord[j] = roundKeys[i - 1, j];

                if (i % Nk == 0)
                {
                    byte shift = tempWord[0];
                    for (int j = 0; j < 3; j++)
                        tempWord[j] = tempWord[j + 1];

                    tempWord[3] = shift;

                    for (int j = 0; j < 4; j++)
                        tempWord[j] = sBox[tempWord[j]];

                    tempWord[0] = (byte) (tempWord[0] ^  Rcon[i / Nk][0]);
                }

                for (int j = 0; j < 4; j++)
                    roundKeys[i, j] = (byte) (roundKeys[i - Nk, j] ^ tempWord[j]);
            }
        }

        private void AddRoundKey(int round)
        {
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    state[j, i] ^= roundKeys[round * 4 + i, j];
        }

        private void SubBytes()
        {
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    state[i, j] = sBox[state[i, j]];
        }

        private void InvertSubBytes()
        {
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    state[i, j] = InvertSBox[state[i, j]];
        }

        private void ShiftRows()
        {
            byte temp = state[1, 0];
            state[1, 0] = state[1, 1];
            state[1, 1] = state[1, 2];
            state[1, 2] = state[1, 3];
            state[1, 3] = temp;

            temp = state[2, 0];
            state[2, 0] = state[2, 2];
            state[2, 1] = state[2, 3];
            state[2, 2] = temp;
            state[2, 3] = state[2, 1];

            temp = state[3, 0];
            state[3, 0] = state[3, 3];
            state[3, 1] = temp;
            state[3, 2] = state[3, 1];
            state[3, 3] = state[3, 2];
        }

        private void InvertShifRows()
        {
            byte temp = state[1, 3];
            state[1, 3] = state[1, 2];
            state[1, 2] = state[1, 1];
            state[1, 1] = state[1, 0];
            state[1, 0] = temp;

            temp = state[2, 1];
            state[2, 1] = state[2, 3];
            state[2, 3] = temp;
            temp = state[2, 0];
            state[2, 0] = state[2, 2];
            state[2, 2] = temp;

            temp = state[3, 0];
            state[3, 0] = state[3, 1];
            state[3, 1] = state[3, 2];
            state[3, 2] = state[3, 3];
            state[3, 3] = temp;
        }

        private void MixColumns()
        {
            for (int i = 0; i < 4; i++)
            {
                byte a, b, c, d, e, f;

                a = state[0, i];
                b = (byte) (state[0, i] ^ state[1, i] ^ state[2, i] ^ state[3, i]);
                c = xTime((byte) (state[0, i] ^ state[1, i]));

                state[0, i] = (byte) (state[0, i] ^ c ^ b);

                d = xTime((byte) (state[1, i] ^ state[2, i]));
                state[1, i] = (byte) (state[1, i] ^ d ^ b);

                e = xTime((byte) (state[2, i] ^ state[3, i]));
                state[2, i] = (byte) (state[2, i] ^ e ^ b);

                f = xTime((byte) (state[3, i] ^ a));
                state[3, i] = (byte) (state[3, i] ^ f ^ b);
            }
        }

        private void InvertMixColumns()
        {
            for (int i = 0; i < 4; i++)
            {
                byte x1 = state[0, i];
                byte x2 = state[1, i];
                byte x3 = state[2, i];
                byte x4 = state[3, i];

                state[0, i] = (byte) (Multiply(x1, 14) ^ Multiply(x2, 11) ^ Multiply(x3, 13) ^ Multiply(x4, 9));
                state[1, i] = (byte) (Multiply(x1, 9) ^ Multiply(x2, 14) ^ Multiply(x3, 11) ^ Multiply(x4, 13));
                state[2, i] = (byte) (Multiply(x1, 13) ^ Multiply(x2, 9) ^ Multiply(x3, 14) ^ Multiply(x4, 11));
                state[3, i] = (byte) (Multiply(x1, 11) ^ Multiply(x2, 13) ^ Multiply(x3, 9) ^ Multiply(x4, 14));
            }
        }

        private byte xTime(byte x)
        {
            return (byte) ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
        }

        private byte Multiply(byte x, byte y)
        {
            return (byte) ((y & 1) * x ^ (y >> 1 & 1) * xTime(x) ^ (y >> 2 & 1) * xTime(xTime(x)) ^ (y >> 3 & 1) * xTime(xTime(xTime(x))) ^ (y >> 4 & 1) * xTime(xTime(xTime(xTime(x)))));
        }
    }
}