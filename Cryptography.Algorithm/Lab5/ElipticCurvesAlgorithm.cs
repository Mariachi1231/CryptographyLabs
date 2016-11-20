using System;
using System.Security.AccessControl;
using System.Security.Policy;
using System.Text;
using Cryptography.Algorithm.Math;

namespace Cryptography.Algorithm.Lab5
{ 
    public class ElipticCurvesAlgorithm : CryptoAlgorithm
    {
        private readonly BigInteger p = new BigInteger("6277101735386680763835789423207666416083908700390324961279", 10);
        private readonly BigInteger b = new BigInteger("2455155546008943817740293915197451784769108058161191238065", 10);
        private readonly BigInteger n = new BigInteger("ffffffffffffffffffffffff99def836146bc9b1b4d22831", 16);

        private readonly BigInteger a = -3;
        private readonly BigInteger h = 1;

        private byte[] H;

        private byte[] xG;

        private ECPoint G = new ECPoint();

        public ElipticCurvesAlgorithm()
        {
        }

        private StribogHashAlgorithm hash;

        private string signature;

        public ECPoint PublicKey { get; private set; }

        public override string Encrypt(string strToEncryption)
        {
            base.Encrypt(strToEncryption);

            xG = FromHexStringToByte("03188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012");

            BigInteger d = GeneratePrivateKey(192);
            PublicKey = GeneratePublicKey(d);

            hash = new StribogHashAlgorithm(256);
            H = hash.GetHash(Encoding.Default.GetBytes(strToEncryption));

            signature = GenerateSignature(H, d);

            return signature;
        }

        public override string Decrypt(string strToDecryption)
        {
            base.Decrypt(strToDecryption);

            hash = new StribogHashAlgorithm(256);
            return VerifySignature(H, strToDecryption) ? "Verified" : "Denied";
        }

        private BigInteger GeneratePrivateKey(int BitSize)
        {
            BigInteger d = new BigInteger();
            d.genRandomBits(BitSize, new Random());

            return d;
        }

        private ECPoint GeneratePublicKey(BigInteger d)
        {
            ECPoint G = GDecompression();
            PublicKey = ECPoint.Multiply(d, G);
            return PublicKey;
        }

        private string GenerateSignature(byte[] h, BigInteger d)
        {
            BigInteger alpha = new BigInteger(h);
            BigInteger e = alpha % n;

            if (e == 0)
                e = 1;

            BigInteger k = new BigInteger();
            ECPoint c = new ECPoint();
            BigInteger r = new BigInteger();
            BigInteger s = new BigInteger();

            do
            {
                do
                {
                    k.genRandomBits(n.bitCount(), new Random());
                } while ((k < 0) || (k > n));

                c = ECPoint.Multiply(k, G);
                r = c.x % n;
                s = ((r * d) + (k * e)) % n;
            } while ((r == 0) || (s == 0));

            string Rvector = Padding(r.ToHexString(), n.bitCount() / 4);
            string Svector = Padding(s.ToHexString(), n.bitCount() / 4);

            return Rvector + Svector;
        }

        private string Padding(string input, int size)
        {
            if (input.Length < size)
            {
                do
                {
                    input += "0";
                } while (input.Length < size);
            }

            return input;;
        }

        private bool VerifySignature(byte[] H, string sign)
        {
            string Rvector = sign.Substring(0, n.bitCount() / 4);
            string Svector = sign.Substring(n.bitCount() / 4, n.bitCount() / 4);

            BigInteger r = new BigInteger(Rvector, 16);
            BigInteger s = new BigInteger(Svector, 16);

            if ((r < 1) || (r > (n - 1)) || (s < 1) || (s > (n - 1)))
                return false;

            BigInteger alpha = new BigInteger(H);
            BigInteger e = alpha % n;

            if (e == 0)
                e = 1;

            BigInteger v = e.modInverse(n);
            BigInteger z1 = (s * v) % n;
            BigInteger z2 = n + ((- (r * v)) % n);

            this.G = GDecompression();

            ECPoint A = ECPoint.Multiply(z1, G);
            ECPoint B = ECPoint.Multiply(z2, PublicKey);

            ECPoint C = A + B;
            BigInteger R = C.x % n;

            if (R == r)
                return true;
            else return false;
        }

        private byte[] FromHexStringToByte(string input)
        {
            byte[] data = new byte[input.Length / 2];
            string HexByte = "";
            for (int i = 0; i < data.Length; i++)
            {
                HexByte = input.Substring(i * 2, 2);
                data[i] = Convert.ToByte(HexByte, 16);
            }
            return data;
        }

        private ECPoint GDecompression()
        {
            byte y = xG[0];
            byte[] x = new byte[xG.Length - 1];
            Array.Copy(xG, 1, x, 0, xG.Length - 1);
            BigInteger Xcord = new BigInteger(x);
            BigInteger temp = (Xcord * Xcord * Xcord + a * Xcord + b) % p;
            BigInteger beta = ModSqrt(temp, p);
            BigInteger Ycord = new BigInteger();
            if ((beta % 2) == (y % 2))
                Ycord = beta;
            else
                Ycord = p - beta;
            ECPoint G = new ECPoint();
            G.a = a;
            G.b = b;
            G.FieldChar = p;
            G.x = Xcord;
            G.y = Ycord;
            this.G = G;
            return G;
        }

        public BigInteger ModSqrt(BigInteger a, BigInteger q)
        {
            BigInteger b = new BigInteger();
            do
            {
                b.genRandomBits(255, new Random());
            } while (Legendre(b, q) == 1);
            BigInteger s = 0;
            BigInteger t = q - 1;
            while ((t & 1) != 1)
            {
                s++;
                t = t >> 1;
            }
            BigInteger InvA = a.modInverse(q);
            BigInteger c = b.modPow(t, q);
            BigInteger r = a.modPow(((t + 1) / 2), q);
            BigInteger d = new BigInteger();
            for (int i = 1; i < s; i++)
            {
                BigInteger temp = 2;
                temp = temp.modPow((s - i - 1), q);
                d = (r.modPow(2, q) * InvA).modPow(temp, q);
                if (d == (q - 1))
                    r = (r * c) % q;
                c = c.modPow(2, q);
            }
            return r;
        }

        public BigInteger Legendre(BigInteger a, BigInteger q)
        {
            return a.modPow((q - 1) / 2, q);
        }

    }
}