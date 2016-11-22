using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cryptography.Algorithm.Lab7
{
    public class AES : CryptoAlgorithm
    { 
        private int Nr = 4;
        private int Nk = 4;
        private byte[] RoundKey = new byte[176];
        private byte[] Key = new byte[16];
        private byte[] bIn = new byte[16];
        private byte[] bOut = new byte[16];
        private byte[,] state = new byte[4, 4];
        private int iSubBytesInd = new Random().Next(7) + 1;
        private byte[,] SubBytesIn = new byte[4, 4];
        private byte[,] SubBytesOut = new byte[4, 4];
        private byte[,] ShiftRowsIn = new byte[4, 4];
        private byte[,] ShiftRowsOut = new byte[4, 4];
        private byte[,] MixColumnsIn = new byte[4, 4];
        private byte[,] MixColumnsOut = new byte[4, 4];
        private byte[,] AddRoundKeyIn = new byte[4, 4];
        private byte[,] AddRoundKeyOut = new byte[4, 4];
        private byte[,] InvSubBytesIn = new byte[4, 4];
        private byte[,] InvSubBytesOut = new byte[4, 4];
        private byte[,] InvShiftRowsIn = new byte[4, 4];
        private byte[,] InvShiftRowsOut = new byte[4, 4];
        private byte[,] InvMixColumnsIn = new byte[4, 4];
        private byte[,] InvMixColumnsOut = new byte[4, 4];
        private byte[,] InvAddRoundKeyIn = new byte[4, 4];
        private byte[,] InvAddRoundKeyOut = new byte[4, 4];
        private int[] sbox = new int[256]
        {
            99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118, 202, 130, 201, 125, 250, 89, 71,
            240, 173, 212, 162, 175, 156, 164, 114, 192, 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216,
            49, 21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160,
            82, 59, 214, 179, 41, 227, 47, 132, 83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208,
            239, 170, 251, 67, 77, 51, 133, 69, 249, 2, (int) sbyte.MaxValue, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157,
            56, 245, 188, 182, 218, 33, 16, (int) byte.MaxValue, 243, 210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167,
            126, 61, 100, 93, 25, 115, 96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58,
            10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244,
            234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138, 112, 62,
            181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225, 248, 152, 17, 105, 217, 142, 148, 155, 30,
            135, 233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187,22
        };

        private int[] rsbox = new int[256]
        {
             82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251, 124, 227, 57, 130,
             155, 47, (int) byte.MaxValue, 135, 52, 142, 67, 68, 196, 222, 233, 203, 84, 123, 148, 50,
             166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 195, 78, 8, 46, 161, 102, 40, 217, 36, 178,
             118, 91, 162, 73, 109, 139, 209, 37, 114, 248, 246, 100, 134, 104, 152, 22, 212, 164, 92,
             204, 93, 101, 182, 146, 108, 112, 72, 80, 253, 237, 185, 218, 94, 21, 70, 87, 167, 141,
             157, 132, 144, 216, 171, 0, 140, 188, 211, 10, 247, 228, 88, 5, 184, 179, 69, 6, 208, 44,
             30, 143, 202, 63, 15, 2, 193, 175, 189, 3, 1, 19, 138, 107, 58, 145, 17, 65, 79, 103, 220,
             234, 151, 242, 207, 206, 240, 180, 230, 115, 150, 172, 116, 34, 231, 173, 53, 133, 226,
             249, 55, 232, 28, 117, 223, 110, 71, 241, 26, 113, 29, 41, 197, 137, 111, 183, 98, 14, 170,
             24, 190, 27, 252, 86, 62, 75, 198, 210, 121, 32, 154, 219, 192, 254, 120, 205, 90, 244, 31,
             221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95, 96, 81, (int) sbyte.MaxValue,
             169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239, 160, 224, 59, 77, 174, 42, 245,
             176, 200, 235, 187, 60, 131, 83, 153, 97, 23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125
        };

        private int[] Rcon = new int[(int) byte.MaxValue]
        {
             141, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108, 216, 171, 77, 154, 47, 94, 188, 99, 198, 151,
             53, 106, 212, 179, 125, 250, 239, 197, 145, 57, 114, 228, 211, 189, 97, 194, 159, 37, 74,
             148, 51, 102, 204, 131, 29, 58, 116, 232, 203, 141, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54,
             108, 216, 171, 77, 154, 47, 94, 188, 99, 198, 151, 53, 106, 212, 179, 125, 250, 239, 197,
             145, 57, 114, 228, 211, 189, 97, 194, 159, 37, 74, 148, 51, 102, 204, 131, 29, 58, 116,
             232, 203, 141, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108, 216, 171, 77, 154, 47, 94, 188,
             99, 198, 151, 53, 106, 212, 179, 125, 250, 239, 197, 145, 57, 114, 228, 211, 189, 97, 194,
             159, 37, 74, 148, 51, 102, 204, 131, 29, 58, 116, 232, 203, 141, 1, 2, 4, 8, 16, 32, 64,
             128, 27, 54, 108, 216, 171, 77, 154, 47, 94, 188, 99, 198, 151, 53, 106, 212, 179, 125,
             250, 239, 197, 145, 57, 114, 228, 211, 189, 97, 194, 159, 37, 74, 148, 51, 102, 204, 131,
             29, 58, 116, 232, 203, 141, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108, 216, 171, 77, 154,
             47, 94, 188, 99, 198, 151, 53, 106, 212, 179, 125, 250, 239, 197, 145, 57, 114, 228, 211,
             189, 97, 194, 159, 37, 74, 148, 51, 102, 204, 131, 29, 58, 116, 232, 203
        };
        private const int Nb = 4;
        private byte[] bData;

        private byte getSBoxValue(int num)
        {
            return (byte) this.sbox[num];
        }

        private byte getSBoxInvert(int num)
        {
            return (byte) this.rsbox[num];
        }

        private void KeyExpansion()
        {
            byte[] numArray = new byte[4];
            int num1;
            for (num1 = 0; num1 < this.Nk; ++num1)
            {
                this.RoundKey[num1 * 4] = this.Key[num1 * 4];
                this.RoundKey[num1 * 4 + 1] = this.Key[num1 * 4 + 1];
                this.RoundKey[num1 * 4 + 2] = this.Key[num1 * 4 + 2];
                this.RoundKey[num1 * 4 + 3] = this.Key[num1 * 4 + 3];
            }
            for (; num1 < 4 * (this.Nr + 1); ++num1)
            {
                for (int index = 0; index < 4; ++index)
                    numArray[index] = this.RoundKey[(num1 - 1) * 4 + index];
                if (num1 % this.Nk == 0)
                {
                    byte num2 = numArray[0];
                    numArray[0] = numArray[1];
                    numArray[1] = numArray[2];
                    numArray[2] = numArray[3];
                    numArray[3] = num2;
                    numArray[0] = this.getSBoxValue((int) numArray[0]);
                    numArray[1] = this.getSBoxValue((int) numArray[1]);
                    numArray[2] = this.getSBoxValue((int) numArray[2]);
                    numArray[3] = this.getSBoxValue((int) numArray[3]);
                    numArray[0] = (byte) ((uint) numArray[0] ^ (uint) this.Rcon[num1 / this.Nk]);
                } else if (this.Nk > 6 && num1 % this.Nk == 4)
                {
                    numArray[0] = this.getSBoxValue((int) numArray[0]);
                    numArray[1] = this.getSBoxValue((int) numArray[1]);
                    numArray[2] = this.getSBoxValue((int) numArray[2]);
                    numArray[3] = this.getSBoxValue((int) numArray[3]);
                }
                this.RoundKey[num1 * 4] = (byte) ((uint) this.RoundKey[(num1 - this.Nk) * 4] ^ (uint) numArray[0]);
                this.RoundKey[num1 * 4 + 1] = (byte) ((uint) this.RoundKey[(num1 - this.Nk) * 4 + 1] ^ (uint) numArray[1]);
                this.RoundKey[num1 * 4 + 2] = (byte) ((uint) this.RoundKey[(num1 - this.Nk) * 4 + 2] ^ (uint) numArray[2]);
                this.RoundKey[num1 * 4 + 3] = (byte) ((uint) this.RoundKey[(num1 - this.Nk) * 4 + 3] ^ (uint) numArray[3]);
            }
        }

        private void AddRoundKey(int round)
        {
            for (int index1 = 0; index1 < 4; ++index1)
            {
                for (int index2 = 0; index2 < 4; ++index2)
                    this.state[index2, index1] ^= this.RoundKey[round * 4 * 4 + index1 * 4 + index2];
            }
        }

        private void SubBytes()
        {
            for (int index1 = 0; index1 < 4; ++index1)
            {
                for (int index2 = 0; index2 < 4; ++index2)
                    this.state[index1, index2] = this.getSBoxValue((int) this.state[index1, index2]);
            }
        }

        private void InvSubBytes()
        {
            for (int index1 = 0; index1 < 4; ++index1)
            {
                for (int index2 = 0; index2 < 4; ++index2)
                    this.state[index1, index2] = this.getSBoxInvert((int) this.state[index1, index2]);
            }
        }

        private void ShiftRows()
        {
            byte num1 = this.state[1, 0];
            this.state[1, 0] = this.state[1, 1];
            this.state[1, 1] = this.state[1, 2];
            this.state[1, 2] = this.state[1, 3];
            this.state[1, 3] = num1;
            byte num2 = this.state[2, 0];
            this.state[2, 0] = this.state[2, 2];
            this.state[2, 2] = num2;
            byte num3 = this.state[2, 1];
            this.state[2, 1] = this.state[2, 3];
            this.state[2, 3] = num3;
            byte num4 = this.state[3, 0];
            this.state[3, 0] = this.state[3, 3];
            this.state[3, 3] = this.state[3, 2];
            this.state[3, 2] = this.state[3, 1];
            this.state[3, 1] = num4;
        }

        private void InvShiftRows()
        {
            byte num1 = this.state[1, 3];
            this.state[1, 3] = this.state[1, 2];
            this.state[1, 2] = this.state[1, 1];
            this.state[1, 1] = this.state[1, 0];
            this.state[1, 0] = num1;
            byte num2 = this.state[2, 0];
            this.state[2, 0] = this.state[2, 2];
            this.state[2, 2] = num2;
            byte num3 = this.state[2, 1];
            this.state[2, 1] = this.state[2, 3];
            this.state[2, 3] = num3;
            byte num4 = this.state[3, 0];
            this.state[3, 0] = this.state[3, 1];
            this.state[3, 1] = this.state[3, 2];
            this.state[3, 2] = this.state[3, 3];
            this.state[3, 3] = num4;
        }

        private byte xtime(byte x)
        {
            return (byte) (this.Rotl((uint) x, 1U) ^ (uint) (((int) this.Rotr((uint) x, 7U) & 1) * 27));
        }

        private byte Multiply(byte x, byte y)
        {
            return (byte) (((int) y & 1) * (int) x ^ ((int) y >> 1 & 1) * (int) this.xtime(x) ^ ((int) y >> 2 & 1) * (int) this.xtime(this.xtime(x)) ^ ((int) y >> 3 & 1) * (int) this.xtime(this.xtime(this.xtime(x))) ^ ((int) y >> 4 & 1) * (int) this.xtime(this.xtime(this.xtime(this.xtime(x)))));
        }

        private void MixColumns()
        {
            for (int index = 0; index < 4; ++index)
            {
                byte num1 = this.state[0, index];
                byte num2 = (byte) ((uint) this.state[0, index] ^ (uint) this.state[1, index] ^ (uint) this.state[2, index] ^ (uint) this.state[3, index]);
                byte num3 = this.xtime((byte) ((uint) this.state[0, index] ^ (uint) this.state[1, index]));
                this.state[0, index] = (byte) ((uint) this.state[0, index] ^ (uint) num3 ^ (uint) num2);
                byte num4 = this.xtime((byte) ((uint) this.state[1, index] ^ (uint) this.state[2, index]));
                this.state[1, index] = (byte) ((uint) this.state[1, index] ^ (uint) num4 ^ (uint) num2);
                byte num5 = this.xtime((byte) ((uint) this.state[2, index] ^ (uint) this.state[3, index]));
                this.state[2, index] = (byte) ((uint) this.state[2, index] ^ (uint) num5 ^ (uint) num2);
                byte num6 = this.xtime((byte) ((uint) this.state[3, index] ^ (uint) num1));
                this.state[3, index] = (byte) ((uint) this.state[3, index] ^ (uint) num6 ^ (uint) num2);
            }
        }

        private void InvMixColumns()
        {
            for (int index = 0; index < 4; ++index)
            {
                byte x1 = this.state[0, index];
                byte x2 = this.state[1, index];
                byte x3 = this.state[2, index];
                byte x4 = this.state[3, index];
                this.state[0, index] = (byte) ((uint) this.Multiply(x1, (byte) 14) ^ (uint) this.Multiply(x2, (byte) 11) ^ (uint) this.Multiply(x3, (byte) 13) ^ (uint) this.Multiply(x4, (byte) 9));
                this.state[1, index] = (byte) ((uint) this.Multiply(x1, (byte) 9) ^ (uint) this.Multiply(x2, (byte) 14) ^ (uint) this.Multiply(x3, (byte) 11) ^ (uint) this.Multiply(x4, (byte) 13));
                this.state[2, index] = (byte) ((uint) this.Multiply(x1, (byte) 13) ^ (uint) this.Multiply(x2, (byte) 9) ^ (uint) this.Multiply(x3, (byte) 14) ^ (uint) this.Multiply(x4, (byte) 11));
                this.state[3, index] = (byte) ((uint) this.Multiply(x1, (byte) 11) ^ (uint) this.Multiply(x2, (byte) 13) ^ (uint) this.Multiply(x3, (byte) 9) ^ (uint) this.Multiply(x4, (byte) 14));
            }
        }

        public override string Encrypt(string text)
        {
            bIn = Encoding.ASCII.GetBytes(text);
            for (int index1 = 0; index1 < 4; ++index1)
            {
                for (int index2 = 0; index2 < 4; ++index2)
                    this.state[index2, index1] = this.bIn[index1 * 4 + index2];
            }
            this.AddRoundKey(0);
            for (int round = 1; round < this.Nr; ++round)
            {
                if (round == this.iSubBytesInd)
                {
                    for (int index = 0; index < 16; ++index)
                        this.SubBytesIn[index % 4, index / 4] = this.state[index % 4, index / 4];
                }
                this.SubBytes();
                if (round == this.iSubBytesInd)
                {
                    for (int index = 0; index < 16; ++index)
                        this.SubBytesOut[index % 4, index / 4] = this.state[index % 4, index / 4];
                }
                if (round == this.iSubBytesInd)
                {
                    for (int index = 0; index < 16; ++index)
                        this.ShiftRowsIn[index % 4, index / 4] = this.state[index % 4, index / 4];
                }
                this.ShiftRows();
                if (round == this.iSubBytesInd)
                {
                    for (int index = 0; index < 16; ++index)
                        this.ShiftRowsOut[index % 4, index / 4] = this.state[index % 4, index / 4];
                }
                if (round == this.iSubBytesInd)
                {
                    for (int index = 0; index < 16; ++index)
                        this.MixColumnsIn[index % 4, index / 4] = this.state[index % 4, index / 4];
                }
                this.MixColumns();
                if (round == this.iSubBytesInd)
                {
                    for (int index = 0; index < 16; ++index)
                        this.MixColumnsOut[index % 4, index / 4] = this.state[index % 4, index / 4];
                }
                if (round == this.iSubBytesInd)
                {
                    for (int index = 0; index < 16; ++index)
                        this.AddRoundKeyIn[index % 4, index / 4] = this.state[index % 4, index / 4];
                }
                this.AddRoundKey(round);
                if (round == this.iSubBytesInd)
                {
                    for (int index = 0; index < 16; ++index)
                        this.AddRoundKeyOut[index % 4, index / 4] = this.state[index % 4, index / 4];
                }
            }
            this.SubBytes();
            this.ShiftRows();
            this.AddRoundKey(this.Nr);
            for (int index1 = 0; index1 < 4; ++index1)
            {
                for (int index2 = 0; index2 < 4; ++index2)
                    this.bOut[index1 * 4 + index2] = this.state[index2, index1];
            }
            return Encoding.ASCII.GetString(bOut);
        }

        public override string Decrypt(string text)
        {
            //bIn = Encoding.ASCII.GetBytes(text);
            for (int index1 = 0; index1 < 4; ++index1)
            {
                for (int index2 = 0; index2 < 4; ++index2)
                    this.state[index2, index1] = this.bOut[index1 * 4 + index2];
            }
            this.AddRoundKey(this.Nr);
            for (int round = this.Nr - 1; round > 0; --round)
            {
                if (round == this.iSubBytesInd)
                {
                    for (int index = 0; index < 16; ++index)
                        this.InvShiftRowsIn[index % 4, index / 4] = this.state[index % 4, index / 4];
                }
                this.InvShiftRows();
                if (round == this.iSubBytesInd)
                {
                    for (int index = 0; index < 16; ++index)
                        this.InvShiftRowsOut[index % 4, index / 4] = this.state[index % 4, index / 4];
                }
                if (round == this.iSubBytesInd)
                {
                    for (int index = 0; index < 16; ++index)
                        this.InvSubBytesIn[index % 4, index / 4] = this.state[index % 4, index / 4];
                }
                this.InvSubBytes();
                if (round == this.iSubBytesInd)
                {
                    for (int index = 0; index < 16; ++index)
                        this.InvSubBytesOut[index % 4, index / 4] = this.state[index % 4, index / 4];
                }
                if (round == this.iSubBytesInd)
                {
                    for (int index = 0; index < 16; ++index)
                        this.InvAddRoundKeyIn[index % 4, index / 4] = this.state[index % 4, index / 4];
                }
                this.AddRoundKey(round);
                if (round == this.iSubBytesInd)
                {
                    for (int index = 0; index < 16; ++index)
                        this.InvAddRoundKeyOut[index % 4, index / 4] = this.state[index % 4, index / 4];
                }
                if (round == this.iSubBytesInd)
                {
                    for (int index = 0; index < 16; ++index)
                        this.InvMixColumnsIn[index % 4, index / 4] = this.state[index % 4, index / 4];
                }
                this.InvMixColumns();
                if (round == this.iSubBytesInd)
                {
                    for (int index = 0; index < 16; ++index)
                        this.InvMixColumnsOut[index % 4, index / 4] = this.state[index % 4, index / 4];
                }
            }
            this.InvShiftRows();
            this.InvSubBytes();
            this.AddRoundKey(0);
            for (int index1 = 0; index1 < 4; ++index1)
            {
                for (int index2 = 0; index2 < 4; ++index2)
                    this.bOut[index1 * 4 + index2] = this.state[index2, index1];
            }
            return Encoding.ASCII.GetString(bOut);
        }

        private uint Rotl(uint a, uint s)
        {
            if ((int) (s % 32U) == 0)
                return a;
            return a * (uint) System.Math.Pow(2.0, (double) (s % 32U)) | a / (uint) System.Math.Pow(2.0, (double) (32U - s % 32U));
        }

        private uint Rotr(uint a, uint s)
        {
            return this.Rotl(a, 32U - s);
        }
    }
}
