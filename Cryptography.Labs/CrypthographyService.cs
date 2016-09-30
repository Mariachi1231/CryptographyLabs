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
    public class CrypthographyService : ServiceBase
    {
        private ICryptoAlgorithm cryptoAlgorithm;

        public CrypthographyService(IMessageWriter messageWriter, ICryptoAlgorithm cryptoMaster)
            : base(messageWriter)
        {
            if (cryptoMaster == null)
                throw new ArgumentNullException("cryptoMaster");
            this.cryptoAlgorithm = cryptoMaster;
        }

        public ICryptoAlgorithm CryptoMaster { get { return this.cryptoAlgorithm; } }
    }
}
