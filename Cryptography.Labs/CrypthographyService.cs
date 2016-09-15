using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Cryptography.Algorithm;
using Cryptography.Infostructure;
using Cryptography.UI;

namespace Cryptography.Labs
{
    public class CrypthographyService
    {
        private readonly IMessageWriter messageWriter;

        private readonly ICryptoAlgorithm cryptoMaster;

        public CrypthographyService(IMessageWriter messageWriter, ICryptoAlgorithm cryptoMaster)
        {
            if (messageWriter == null)
                throw new ArgumentNullException("messageWriter");

            if (cryptoMaster == null)
                throw new ArgumentNullException("cryptoMaster");

            this.messageWriter = messageWriter;
            this.cryptoMaster = cryptoMaster;
        }

        public IMessageWriter MessageWriter { get { return this.messageWriter; } }

        public ICryptoAlgorithm CryptoMaster { get { return this.cryptoMaster; } }
    }
}
