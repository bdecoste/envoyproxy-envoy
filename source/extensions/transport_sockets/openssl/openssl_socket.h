#pragma once

#include "envoy/network/transport_socket.h"

#include "common/buffer/buffer_impl.h"
#include "common/network/raw_buffer_socket.h"
#include "extensions/transport_sockets/openssl/context_impl.h"
#include "extensions/transport_sockets/openssl/bssl_wrapper.h"

#include "envoy/secret/secret_callbacks.h"

#include "envoy/stats/stats_macros.h"

#include "openssl/ssl.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Openssl {

// clang-format off
#define ALL_SSL_SOCKET_FACTORY_STATS(COUNTER)                                 \
  COUNTER(ssl_context_update_by_sds)                                          \
  COUNTER(upstream_context_secrets_not_ready)                                 \
  COUNTER(downstream_context_secrets_not_ready)
// clang-format on

struct OpensslSocketFactoryStats {
  ALL_SSL_SOCKET_FACTORY_STATS(GENERATE_COUNTER_STRUCT)
};

enum class InitialState { Client, Server };

/**
 * A implementation of Network::TransportSocket based on gRPC TSI
 */
class OpensslSocket : public Network::TransportSocket,
                      public Logger::Loggable<Logger::Id::connection> {
public:
  // For Test
  OpensslSocket(Network::TransportSocketPtr&& raw_socket_ptr);

  /**
   * @param handshaker_factory a function to initiate a OpensslHandshaker
   * @param handshake_validator a function to validate the peer. Called right
   * after the handshake completed with peer data to do the peer validation.
   * The connection will be closed immediately if it returns false.
   */
  OpensslSocket();

  OpensslSocket(Envoy::Ssl::ContextSharedPtr ctx, InitialState state,
              Network::TransportSocketOptionsSharedPtr transport_socket_options);

  // Network::TransportSocket
  void setTransportSocketCallbacks(Envoy::Network::TransportSocketCallbacks& callbacks) override;
  std::string protocol() const override;
  bool canFlushClose() override { return handshake_complete_; }
  const Envoy::Ssl::Connection* ssl() const override { return nullptr; }
  Network::IoResult doWrite(Buffer::Instance& buffer, bool end_stream) override;
  void closeSocket(Network::ConnectionEvent event) override;
  Network::IoResult doRead(Buffer::Instance& buffer) override;
  void onConnected() override;

private:
  Network::PostIoAction doHandshake();
  //void doHandshakeNext();
  //Network::PostIoAction doHandshakeNextDone(NextResultPtr&& next_result);

  //HandshakerFactory handshaker_factory_;
  //HandshakeValidator handshake_validator_;
  //OpensslHandshakerPtr handshaker_{};
  //bool handshaker_next_calling_{};

  //OpensslFrameProtectorPtr frame_protector_;

  Envoy::Network::TransportSocketCallbacks* callbacks_{};
  //NoOpTransportSocketCallbacksPtr noop_callbacks_;
  Network::TransportSocketPtr raw_buffer_socket_;

  Envoy::Buffer::OwnedImpl raw_read_buffer_;
  Envoy::Buffer::OwnedImpl raw_write_buffer_;
  bool handshake_complete_{};
  //bool end_stream_read_{};
  //bool read_error_{};

  bool shutdown_sent_{};
  uint64_t bytes_to_retry_{};

  ContextImplSharedPtr ctx_;
  bssl::UniquePtr<SSL> ssl_;

  void drainErrorQueue();
  void shutdownSsl();
};

/**
 * An implementation of Network::TransportSocketFactory for OpensslSocket
 */
class OpensslSocketFactory : public Network::TransportSocketFactory {
public:
  OpensslSocketFactory();

  bool implementsSecureTransport() const override;
  Network::TransportSocketPtr
  createTransportSocket(Network::TransportSocketOptionsSharedPtr options) const override;

};

class ClientOpensslSocketFactory : public Network::TransportSocketFactory,
                                   public Secret::SecretCallbacks,
                                   Logger::Loggable<Logger::Id::config> {
public:
  ClientOpensslSocketFactory(Envoy::Ssl::ClientContextConfigPtr config, Envoy::Ssl::ContextManager& manager,
                         Stats::Scope& stats_scope);

  Network::TransportSocketPtr
  createTransportSocket(Network::TransportSocketOptionsSharedPtr options) const override;
  bool implementsSecureTransport() const override;

  // Secret::SecretCallbacks
  void onAddOrUpdateSecret() override;

private:
  Envoy::Ssl::ContextManager& manager_;
  Stats::Scope& stats_scope_;
  OpensslSocketFactoryStats stats_;
  Envoy::Ssl::ClientContextConfigPtr config_;
  mutable absl::Mutex ssl_ctx_mu_;
  Envoy::Ssl::ClientContextSharedPtr ssl_ctx_ GUARDED_BY(ssl_ctx_mu_);
};

class ServerOpensslSocketFactory : public Network::TransportSocketFactory,
                                   public Secret::SecretCallbacks,
                                   Logger::Loggable<Logger::Id::config> {
public:
  ServerOpensslSocketFactory(Envoy::Ssl::ServerContextConfigPtr config, Envoy::Ssl::ContextManager& manager,
                         Stats::Scope& stats_scope, const std::vector<std::string>& server_names);

  Network::TransportSocketPtr
  createTransportSocket(Network::TransportSocketOptionsSharedPtr options) const override;
  bool implementsSecureTransport() const override;

  // Secret::SecretCallbacks
  void onAddOrUpdateSecret() override;

private:
  Envoy::Ssl::ContextManager& manager_;
  Stats::Scope& stats_scope_;
  OpensslSocketFactoryStats stats_;
  Envoy::Ssl::ServerContextConfigPtr config_;
  const std::vector<std::string> server_names_;
  mutable absl::Mutex ssl_ctx_mu_;
  Envoy::Ssl::ServerContextSharedPtr ssl_ctx_ GUARDED_BY(ssl_ctx_mu_);
};

} // namespace Openssl
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
