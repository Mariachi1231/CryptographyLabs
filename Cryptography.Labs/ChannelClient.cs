using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Cryptography.Infostructure;

namespace Cryptography.Labs
{
    public class MessageEventArgs : EventArgs
    {
        public string Message;

        public MessageEventArgs(string message)
        {
            if (String.IsNullOrEmpty(message))
                throw new ArgumentNullException("Invalid message");

            this.Message = message;
        }
    }

    public class ChannelClient
    {
        public static readonly int randomNumberLowLimit  = 100000;
        public static readonly int randomNumberHighLimit = 1000000;

        private ICryptoAlgorithmSettableKey cryptoAlgorithm;

        private string name;
        private string secretInfo;

        public event EventHandler<MessageEventArgs> MessageSent;

        private ChannelClient()
        {
        }

        public ChannelClient(string name)
        {
            Name = name;
        }

        public ChannelClient(string name, ICryptoAlgorithmSettableKey cryptoAlgorithm)
            : this(name)
        {
            CryptoAlgorithm = cryptoAlgorithm;
            secretInfo = GenerateBigInteger(randomNumberLowLimit, randomNumberHighLimit).ToString();
        }
        
        public ICryptoAlgorithmSettableKey CryptoAlgorithm
        {
            get { return this.cryptoAlgorithm; }
            set
            {
                if (value == null)
                    throw new ArgumentNullException("Invalid cryptoAlgorithm. CryptoAlgorithm is equal to null.");

                this.cryptoAlgorithm = value;
            }
        }

        public string Name
        {
            get { return this.name; }
            set
            {
                if (String.IsNullOrEmpty(value))
                    throw new ArgumentNullException("Invalid name.");

                this.name = value;
            }
        }

        public string SecretInfo { get { return this.secretInfo; } }
        
        public string SendMessage(string message, bool encrypt)
        {
            if (encrypt)
                message = cryptoAlgorithm.Encrypt(message);
            MessageSent?.Invoke(this, new MessageEventArgs(message));

            return message;
        }

        public override string ToString()
        {
            return name;
        }

        private int GenerateBigInteger(int lowLimit, int HighLimit)
        {
            Random rand = new Random();
            Thread.Sleep(15);

            return rand.Next(lowLimit, HighLimit);
        }
    }
}
