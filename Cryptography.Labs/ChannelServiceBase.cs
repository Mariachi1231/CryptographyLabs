using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Cryptography.Infostructure;

namespace Cryptography.Labs
{
    public abstract class ChannelServiceBase : ProgramServiceBase, IDisposable
    {
        protected List<ChannelClient> channelClients = new List<ChannelClient>();

        public ChannelServiceBase(IMessageWriter messageWriter)
            : base(messageWriter)
        {
        }

        public abstract void AddClient(ChannelClient client);

        public abstract void RemoveClient(ChannelClient client);

        public abstract void EstablishConnection();

        public abstract void Dispose();

        public virtual void SendMessage(ChannelClient from, string message)
        {
            MessageWriter.WriteMessage($"{from} send message: {message}");
        }

        public virtual void AddClient(IEnumerable<ChannelClient> clients)
        {
            foreach (var client in clients)
                AddClient(client);
        }

        public IReadOnlyCollection<ChannelClient> ChannelClients { get { return channelClients.AsReadOnly(); } }
    }
}
