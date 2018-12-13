#pragma once

#include "envoy/server/transport_socket_config.h"

#include "extensions/transport_sockets/well_known_names.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Openssl {

// ALTS config registry
class OpensslTransportSocketConfigFactory
    : public virtual Server::Configuration::TransportSocketConfigFactory {
public:
  ProtobufTypes::MessagePtr createEmptyConfigProto() override;
  std::string name() const override { return TransportSocketNames::get().Openssl; }
};

class UpstreamOpensslTransportSocketConfigFactory
    : public OpensslTransportSocketConfigFactory,
      public Server::Configuration::UpstreamTransportSocketConfigFactory {
public:
  Network::TransportSocketFactoryPtr
  createTransportSocketFactory(const Protobuf::Message&,
                               Server::Configuration::TransportSocketFactoryContext&) override;
};

class DownstreamOpensslTransportSocketConfigFactory
    : public OpensslTransportSocketConfigFactory,
      public Server::Configuration::DownstreamTransportSocketConfigFactory {
public:
  Network::TransportSocketFactoryPtr
  createTransportSocketFactory(const Protobuf::Message&,
                               Server::Configuration::TransportSocketFactoryContext&,
                               const std::vector<std::string>&) override;
};

} // namespace Openssl
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
