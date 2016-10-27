using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Cryptography.Algorithm.Utils
{
    internal static class LocalExtensions
    {
        internal static string[] IndexOfAll<T>(this T[,] array, T value)
            where T : struct
        {
            List<string> items = new List<string>();

            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < array.GetLength(0); i++)
                for (int j = 0; j < array.GetLength(1); j++)
                    if (array[i, j].Equals(value))
                    {
                        if (i < 10)
                            sb.Append("0").Append(i);
                        else sb.Append(i);

                        if (j < 10)
                            sb.Append("0").Append(j);
                        else sb.Append(j);

                        items.Add(sb.ToString());
                        sb.Clear();
                    }

            return items.ToArray();
        }

        internal static string GetRandomString(this string[] strings)
        {
            Random rand = new Random();
            Thread.Sleep(15);
            return strings[rand.Next(strings.Count() - 1)];
        }

        internal static IEnumerable<byte> ToByteArray(this string str)
        {
            return str.Select(x => Convert.ToByte(x)).ToArray();
        }

        internal static string GetStringEquation(this IEnumerable<byte> byteArray)
        {
            return new string(byteArray.Select(x => (char)x).ToArray());
        }

        internal static IEnumerable<bool> ToBits(this byte bt)
        {
            int size = 8;
            bool[] bits = new bool[size];

            int temp = bt;
            for (int i = 0; i < size; i++)
            {
                if (temp == 0)
                    break;
                
                if (temp % 2 == 1)
                    bits[size - i - 1] = true;
                temp = temp / 2;
            }

            return bits;
        }

        internal static IEnumerable<bool> ConvertFromUIntToBinary(this uint source)
        {
            return ((int) source).ConvertFromIntToBinary();
        } 

        internal static IEnumerable<bool> ToBits(this IEnumerable<byte> bytes)
        {
            var bitSequences = bytes.Select(x => x.ToBits());

            foreach (var bitSequence in bitSequences)
                foreach (var bit in bitSequence)
                    yield return bit;
        }

        internal static IEnumerable<byte> ToBytes(this IEnumerable<bool> bits)
        {
            var bitsSequences = bits.ToChunks(8);
            foreach (var bitsSequence in bitsSequences)
            {
                byte result = 0;
                var bitsArray = bitsSequence.ToArray();
                for (int i = bitsArray.Length - 1; i > -1; i--)
                    if (bitsArray[i])
                        result += (byte) System.Math.Pow(2, bitsArray.Length - 1 - i);

                yield return result;
            }
        }

        internal static IEnumerable<IEnumerable<T>> ToChunks<T>(this IEnumerable<T> items, int chunkSize)
        {
            List<T> chunk = new List<T>(chunkSize);
            foreach (var item in items)
            {
                chunk.Add(item);
                if (chunk.Count == chunkSize)
                {
                    yield return chunk;
                    chunk = new List<T>(chunkSize);
                }
            }

            if (chunk.Any())
                yield return chunk;
        }

        internal static void DivideIntoTwoParts<T>(this IEnumerable<T> sequence, out IEnumerable<T> leftPart, out IEnumerable<T> rightPart)
        {
            int halfSize = sequence.Count() / 2;

            leftPart = sequence.Take(halfSize);
            rightPart = sequence.Skip(halfSize);
        }


        internal static int ConvertFromBinaryToInt(this IEnumerable<bool> bits)
        {
            int result = 0;
            bool[] bitsArray = bits.ToArray();

            if (bitsArray.Length > 32)
                throw new InvalidOperationException("int is to small for this sequence.");

            for (int i = bitsArray.Length - 1; i > -1; i--)
                if (bitsArray[i])
                    result += (int) System.Math.Pow(2, bitsArray.Length - 1 - i);

            return result;
        }

        internal static uint ConvertFromBinaryToUInt(this IEnumerable<bool> bitSequence)
        {
            uint result = 0;
            bool[] bitsArray = bitSequence.ToArray();

            if (bitsArray.Length > 32)
                throw new InvalidOperationException("int is to small for this sequence.");

            for (int i = bitsArray.Length - 1; i > -1; i--)
                if (bitsArray[i])
                    result += (uint) System.Math.Pow(2, bitsArray.Length - 1 - i);

            return result;

        }

        internal static IEnumerable<bool> ConvertFromIntToBinary(this int number)
        {
            List<bool> result = new List<bool>();

            if (number == 0)
                result.Add(false);

            while (number != 0)
            {
                if (number % 2 == 0)
                    result.Add(false);
                else result.Add(true);

                number /= 2;
            }

            result.Reverse();
            return result;
        }

        internal static IEnumerable<bool>AddWhiteSpaceBits(this IEnumerable<bool> bits, int blockSize)
        {
            var bitsArray = bits as bool[] ?? bits.ToArray();
            var sourceSize = bitsArray.Count();

            if (sourceSize > blockSize)
                throw new InvalidOperationException("sourceSize must be less than blockSize.");

            if (sourceSize == blockSize)
                return bitsArray;

            var bitsBlock = new bool[blockSize];

            int i = 0;
            while (i < blockSize - bitsArray.Count())
                bitsBlock[i++] = false;

            foreach (var item in bitsArray)
                bitsBlock[i++] = item;

            return bitsBlock;
        }

        internal static bool[] BitwiseRotation(this IEnumerable<bool> bits, int offset)
        {
            var bitsArray = bits as bool[] ?? bits.ToArray();
            bool[] result = new bool[bitsArray.Length];
            for (int i = 0; i < bitsArray.Length; i++)
            {
                if (i + offset + 1 > bitsArray.Length)
                    result[i] = bitsArray[i + offset - bitsArray.Length];
                else if (i + offset < 0)
                    result[i] = bitsArray[bitsArray.Length + i + offset];
                else
                    result[i] = bitsArray[i + offset];
            }

            return result;
        }

        internal static string StringInvariant(this IEnumerable<bool> bits)
        {
            StringBuilder sb = new StringBuilder();

            int i = 0;
            foreach (var bit in bits)
            {
                if (i++ % 8 == 0 && i != 1)
                    sb.Append(" ");

                if (bit == false)
                    sb.Append("0");
                else sb.Append("1");
            }

            return sb.ToString();
        }
    }
}
