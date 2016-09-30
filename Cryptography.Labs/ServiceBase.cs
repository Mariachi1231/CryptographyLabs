using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Cryptography.Infostructure;

namespace Cryptography.Labs
{
    public abstract class ServiceBase
    {
        private IMessageWriter messageWriter;

        private ServiceBase()
        {
        }

        public ServiceBase(IMessageWriter messageWriter)
        {
            MessageWriter = messageWriter;
        }


        public IMessageWriter MessageWriter
        {
            get { return this.messageWriter; }
            set
            {
                if (value == null)
                    throw new ArgumentNullException("Invalid messageWriter. MessageWriter is equal to null.");

                this.messageWriter = value;
            }
        }
    }
}
