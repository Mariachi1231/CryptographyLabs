using System;
using System.Linq;
using Cryptography.Infostructure;

namespace Cryptography.Labs
{
    public class PeerToPeerChannelService : ChannelServiceBase
    {
        private IKeyGenerator keyGenerator;

        public PeerToPeerChannelService(IMessageWriter messageWriter)
            : base(messageWriter)
        {
        }

        public PeerToPeerChannelService(IMessageWriter messageWriter, IKeyGenerator keyGenerator)
            : this(messageWriter)
        {
            KeyGenerator = keyGenerator;
        }

        public IKeyGenerator KeyGenerator
        {
            set
            {
                if (value == null)
                    throw new ArgumentNullException("Invalid KeyGenerator");

                this.keyGenerator = value;
            }
        }

        public override void AddClient(ChannelClient client)
        {
            if (channelClients.Count > 1)
                throw new InvalidOperationException("The channel allows only two clients.");

            channelClients.Add(client);
            client.MessageSent += Client_MessageSent;

            if (channelClients.Count == 2)
                EstablishConnection();
        }

        public override void RemoveClient(ChannelClient client)
        {
            if (!channelClients.Contains(client))
                throw new InvalidOperationException($"Cannot find the client {client}.");

            client.MessageSent -= Client_MessageSent;
            channelClients.Remove(client);
        }

        public override void Dispose()
        {
            foreach (var client in channelClients)
                client.MessageSent -= Client_MessageSent;

            channelClients.Clear();
        }

        private void Client_MessageSent(object sender, MessageEventArgs e)
        {
            var client = sender as ChannelClient;

            MessageWriter.WriteMessage($"{client} send message: {e.Message}");
        }

        public override void EstablishConnection()
        {
            var client1 = channelClients.ElementAt(0);
            var client2 = channelClients.ElementAt(1);

            var client1AddInfo = keyGenerator.GenerateAdditionalInformation(client1.SecretInfo);
            var client2AddInfo = keyGenerator.GenerateAdditionalInformation(client2.SecretInfo);

            client1.CryptoAlgorithm.SetKey(keyGenerator.GenerateKey(client2AddInfo, client1.SecretInfo));
            client2.CryptoAlgorithm.SetKey(keyGenerator.GenerateKey(client1AddInfo, client2.SecretInfo));
        }

    }
}
