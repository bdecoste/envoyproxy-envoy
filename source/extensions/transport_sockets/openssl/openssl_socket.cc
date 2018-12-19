#include "extensions/transport_sockets/openssl/openssl_socket.h"

#include "common/common/assert.h"
#include "common/common/cleanup.h"
#include "common/common/empty_string.h"
#include "common/common/enum_to_int.h"

#include "openssl/err.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Openssl {

namespace {
// This SslSocket will be used when SSL secret is not fetched from SDS server.
class NotReadySslSocket : public Network::TransportSocket {
public:
  // Network::TransportSocket
  void setTransportSocketCallbacks(Network::TransportSocketCallbacks&) override {}
  std::string protocol() const override { return EMPTY_STRING; }
  bool canFlushClose() override { return true; }
  void closeSocket(Network::ConnectionEvent) override {}
  Network::IoResult doRead(Buffer::Instance&) override { return {Network::PostIoAction::Close, 0, false}; }
  Network::IoResult doWrite(Buffer::Instance&, bool) override {
    return {Network::PostIoAction::Close, 0, false};
  }
  void onConnected() override {}
  const Ssl::Connection* ssl() const override { return nullptr; }
};
} // namespace

OpensslSocket::OpensslSocket(Envoy::Ssl::ContextSharedPtr ctx, InitialState state,
                     Network::TransportSocketOptionsSharedPtr transport_socket_options)
    : ctx_(std::dynamic_pointer_cast<ContextImpl>(ctx)),
      ssl_(ctx_->newSsl(transport_socket_options != nullptr
                            ? transport_socket_options->serverNameOverride()
                            : absl::nullopt)) {
  if (state == InitialState::Client) {
	std::cout << "!!!!!!!!!!!!!!!!!!!!!! OpensslSocket Client " << ssl_.get() << " \n";
    SSL_set_connect_state(ssl_.get());
  } else {
	std::cout << "!!!!!!!!!!!!!!!!!!!!!! OpensslSocket Server " << ssl_.get() << " \n";
    ASSERT(state == InitialState::Server);
    SSL_set_accept_state(ssl_.get());
  }
}

OpensslSocket::OpensslSocket(Network::TransportSocketPtr&& raw_socket)
    : raw_buffer_socket_(std::move(raw_socket)) {}

OpensslSocket::OpensslSocket()
    : OpensslSocket(std::make_unique<Network::RawBufferSocket>()) {}

void OpensslSocket::setTransportSocketCallbacks(Envoy::Network::TransportSocketCallbacks& callbacks) {
  ASSERT(!callbacks_);
  callbacks_ = &callbacks;

  BIO* bio = BIO_new_socket(callbacks_->fd(), 0);
  SSL_set_bio(ssl_.get(), bio, bio);
}

std::string OpensslSocket::protocol() const {
  const unsigned char* proto;
  unsigned int proto_len;
  SSL_get0_alpn_selected(ssl_.get(), &proto, &proto_len);
  return std::string(reinterpret_cast<const char*>(proto), proto_len);
}

Network::PostIoAction OpensslSocket::doHandshake() {
std::cout << "!!!!!!!!!!!!!!!!!!!!!! doHandshake " << ssl_.get() << " \n";
  ASSERT(!handshake_complete_);
  int rc = SSL_do_handshake(ssl_.get());
  if (rc == 1) {
	ENVOY_CONN_LOG(debug, "handshake complete", callbacks_->connection());
	handshake_complete_ = true;
	ctx_->logHandshake(ssl_.get());
	callbacks_->raiseEvent(Network::ConnectionEvent::Connected);

	// It's possible that we closed during the handshake callback.
	return callbacks_->connection().state() == Network::Connection::State::Open
			   ? Network::PostIoAction::KeepOpen
			   :  Network::PostIoAction::Close;
  } else {
	int err = SSL_get_error(ssl_.get(), rc);
	ENVOY_CONN_LOG(debug, "handshake error: {}", callbacks_->connection(), err);
	switch (err) {
	case SSL_ERROR_WANT_READ:
	case SSL_ERROR_WANT_WRITE:
	  return  Network::PostIoAction::KeepOpen;
	default:
	  drainErrorQueue();
	  return  Network::PostIoAction::Close;
	}
  }
}

Network::IoResult OpensslSocket::doRead(Buffer::Instance& read_buffer) {
std::cout << "!!!!!!!!!!!!!!!!!!!!!! doRead " << ssl_.get() << " \n";
 if (!handshake_complete_) {
	Network::PostIoAction action = doHandshake();
	if (action == Network::PostIoAction::Close || !handshake_complete_) {
	  // end_stream is false because either a hard error occurred (action == Close) or
	  // the handhshake isn't complete, so a half-close cannot occur yet.
	  return {action, 0, false};
	}
  }

  bool keep_reading = true;
  bool end_stream = false;
  Network::PostIoAction action = Network::PostIoAction::KeepOpen;
  uint64_t bytes_read = 0;
  while (keep_reading) {
	// We use 2 slices here so that we can use the remainder of an existing buffer chain element
	// if there is extra space. 16K read is arbitrary and can be tuned later.
	Buffer::RawSlice slices[2];
	uint64_t slices_to_commit = 0;
	uint64_t num_slices = read_buffer.reserve(16384, slices, 2);
	for (uint64_t i = 0; i < num_slices; i++) {
	  int rc = SSL_read(ssl_.get(), slices[i].mem_, slices[i].len_);
	  ENVOY_CONN_LOG(trace, "ssl read returns: {}", callbacks_->connection(), rc);
	  if (rc > 0) {
		slices[i].len_ = rc;
		slices_to_commit++;
		bytes_read += rc;
	  } else {
		keep_reading = false;
		int err = SSL_get_error(ssl_.get(), rc);
		switch (err) {
		case SSL_ERROR_WANT_READ:
		  break;
		case SSL_ERROR_ZERO_RETURN:
		  end_stream = true;
		  break;
		case SSL_ERROR_WANT_WRITE:
		// Renegotiation has started. We don't handle renegotiation so just fall through.
		default:
		  drainErrorQueue();
		  action = Network::PostIoAction::Close;
		  break;
		}

		break;
	  }
	}

	if (slices_to_commit > 0) {
	  read_buffer.commit(slices, slices_to_commit);
	  if (callbacks_->shouldDrainReadBuffer()) {
		callbacks_->setReadBufferReady();
		keep_reading = false;
	  }
	}
  }

  return {action, bytes_read, end_stream};
}

void OpensslSocket::drainErrorQueue() {
  bool saw_error = false;
  bool saw_counted_error = false;
  while (uint64_t err = ERR_get_error()) {
    if (ERR_GET_LIB(err) == ERR_LIB_SSL) {
      if (ERR_GET_REASON(err) == SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE) {
        ctx_->stats().fail_verify_no_cert_.inc();
        saw_counted_error = true;
      } else if (ERR_GET_REASON(err) == SSL_R_CERTIFICATE_VERIFY_FAILED) {
        saw_counted_error = true;
      }
    }
    saw_error = true;

    ENVOY_CONN_LOG(debug, "SSL error: {}:{}:{}:{}", callbacks_->connection(), err,
                   ERR_lib_error_string(err), ERR_func_error_string(err),
                   ERR_reason_error_string(err));
  }
  if (saw_error && !saw_counted_error) {
    ctx_->stats().connection_error_.inc();
  }
}

Network::IoResult OpensslSocket::doWrite(Buffer::Instance& write_buffer, bool end_stream) {
std::cout << "!!!!!!!!!!!!!!!!!!!!!! doWrite " << ssl_.get() << " \n";
  ASSERT(!shutdown_sent_ || write_buffer.length() == 0);
  if (!handshake_complete_) {
	Network::PostIoAction action = doHandshake();
	if (action == Network::PostIoAction::Close || !handshake_complete_) {
	  return {action, 0, false};
	}
  }

  uint64_t bytes_to_write;
  if (bytes_to_retry_) {
    bytes_to_write = bytes_to_retry_;
    bytes_to_retry_ = 0;
  } else {
    bytes_to_write = std::min(write_buffer.length(), static_cast<uint64_t>(16384));
  }

  uint64_t total_bytes_written = 0;
  while (bytes_to_write > 0) {
	// TODO(mattklein123): As it relates to our fairness efforts, we might want to limit the number
	// of iterations of this loop, either by pure iterations, bytes written, etc.

	// SSL_write() requires that if a previous call returns SSL_ERROR_WANT_WRITE, we need to call
	// it again with the same parameters. This is done by tracking last write size, but not write
	// data, since linearize() will return the same undrained data anyway.
	ASSERT(bytes_to_write <= write_buffer.length());
	int rc = SSL_write(ssl_.get(), write_buffer.linearize(bytes_to_write), bytes_to_write);
	ENVOY_CONN_LOG(trace, "ssl write returns: {}", callbacks_->connection(), rc);
	if (rc > 0) {
	  ASSERT(rc == static_cast<int>(bytes_to_write));
	  total_bytes_written += rc;
	  write_buffer.drain(rc);
	  bytes_to_write = std::min(write_buffer.length(), static_cast<uint64_t>(16384));
	} else {
	  int err = SSL_get_error(ssl_.get(), rc);
	  switch (err) {
	  case SSL_ERROR_WANT_WRITE:
		bytes_to_retry_ = bytes_to_write;
		break;
	  case SSL_ERROR_WANT_READ:
	  // Renegotiation has started. We don't handle renegotiation so just fall through.
	  default:
		drainErrorQueue();
		return {Network::PostIoAction::Close, total_bytes_written, false};
	  }

	  break;
	}
  }

  if (write_buffer.length() == 0 && end_stream) {
     shutdownSsl();
   }

  return {Network::PostIoAction::KeepOpen, total_bytes_written, false};
}

void OpensslSocket::shutdownSsl() {
  ASSERT(handshake_complete_);
  if (!shutdown_sent_ && callbacks_->connection().state() != Network::Connection::State::Closed) {
    int rc = SSL_shutdown(ssl_.get());
    ENVOY_CONN_LOG(debug, "SSL shutdown: rc={}", callbacks_->connection(), rc);
    drainErrorQueue();
    shutdown_sent_ = true;
  }
}

void OpensslSocket::closeSocket(Network::ConnectionEvent) {
  // Attempt to send a shutdown before closing the socket. It's possible this won't go out if
  // there is no room on the socket. We can extend the state machine to handle this at some point
  // if needed.
  if (handshake_complete_) {
	shutdownSsl();
  }
}

void OpensslSocket::onConnected() {
	ASSERT(!handshake_complete_);
}

OpensslSocketFactory::OpensslSocketFactory(){}

bool OpensslSocketFactory::implementsSecureTransport() const { return true; }

Network::TransportSocketPtr
OpensslSocketFactory::createTransportSocket(Network::TransportSocketOptionsSharedPtr) const {
  return std::make_unique<OpensslSocket>();
}

namespace {
OpensslSocketFactoryStats generateStats(const std::string& prefix, Stats::Scope& store) {
  return {
      ALL_SSL_SOCKET_FACTORY_STATS(POOL_COUNTER_PREFIX(store, prefix + "_ssl_socket_factory."))};
}
} // namespace

ClientOpensslSocketFactory::ClientOpensslSocketFactory(Envoy::Ssl::ClientContextConfigPtr config,
                                                       Envoy::Ssl::ContextManager& manager,
                                                       Stats::Scope& stats_scope)
    : manager_(manager), stats_scope_(stats_scope), stats_(generateStats("client", stats_scope)),
      config_(std::move(config)),
      ssl_ctx_(manager_.createSslClientContext(stats_scope_, *config_)) {
  config_->setSecretUpdateCallback([this]() { onAddOrUpdateSecret(); });
}

Network::TransportSocketPtr ClientOpensslSocketFactory::createTransportSocket(
    Network::TransportSocketOptionsSharedPtr transport_socket_options) const {
  // onAddOrUpdateSecret() could be invoked in the middle of checking the existence of ssl_ctx and
  // creating SslSocket using ssl_ctx. Capture ssl_ctx_ into a local variable so that we check and
  // use the same ssl_ctx to create SslSocket.namespace {
  Envoy::Ssl::ClientContextSharedPtr ssl_ctx;
  {
    absl::ReaderMutexLock l(&ssl_ctx_mu_);
    ssl_ctx = ssl_ctx_;
  }
  if (ssl_ctx) {
    return std::make_unique<OpensslSocket>(std::move(ssl_ctx), InitialState::Client,
                                            transport_socket_options);
  } else {
    ENVOY_LOG(debug, "Create NotReadySslSocket");
    stats_.upstream_context_secrets_not_ready_.inc();
    return std::make_unique<NotReadySslSocket>();
  }
}

bool ClientOpensslSocketFactory::implementsSecureTransport() const { return true; }

void ClientOpensslSocketFactory::onAddOrUpdateSecret() {
  ENVOY_LOG(debug, "Secret is updated.");
  {
    absl::WriterMutexLock l(&ssl_ctx_mu_);
    ssl_ctx_ = manager_.createSslClientContext(stats_scope_, *config_);
  }
  stats_.ssl_context_update_by_sds_.inc();
}

ServerOpensslSocketFactory::ServerOpensslSocketFactory(Envoy::Ssl::ServerContextConfigPtr config,
                                                       Envoy::Ssl::ContextManager& manager,
                                                       Stats::Scope& stats_scope,
                                                       const std::vector<std::string>& server_names)
    : manager_(manager), stats_scope_(stats_scope), stats_(generateStats("server", stats_scope)),
      config_(std::move(config)), server_names_(server_names),
      ssl_ctx_(manager_.createSslServerContext(stats_scope_, *config_, server_names_)) {
  config_->setSecretUpdateCallback([this]() { onAddOrUpdateSecret(); });
}

Network::TransportSocketPtr
ServerOpensslSocketFactory::createTransportSocket(Network::TransportSocketOptionsSharedPtr) const {
  // onAddOrUpdateSecret() could be invoked in the middle of checking the existence of ssl_ctx and
  // creating SslSocket using ssl_ctx. Capture ssl_ctx_ into a local variable so that we check and
  // use the same ssl_ctx to create SslSocket.1
  Envoy::Ssl::ServerContextSharedPtr ssl_ctx;
  {
    absl::ReaderMutexLock l(&ssl_ctx_mu_);
    ssl_ctx = ssl_ctx_;
  }
  if (ssl_ctx) {
    return std::make_unique<OpensslSocket>(std::move(ssl_ctx), InitialState::Server, nullptr);
  } else {
    ENVOY_LOG(debug, "Create NotReadySslSocket");
    stats_.downstream_context_secrets_not_ready_.inc();
    return std::make_unique<NotReadySslSocket>();
  }
}

bool ServerOpensslSocketFactory::implementsSecureTransport() const { return true; }

void ServerOpensslSocketFactory::onAddOrUpdateSecret() {
  ENVOY_LOG(debug, "Secret is updated.");
  {
    absl::WriterMutexLock l(&ssl_ctx_mu_);
    ssl_ctx_ = manager_.createSslServerContext(stats_scope_, *config_, server_names_);
  }
  stats_.ssl_context_update_by_sds_.inc();
}

} // namespace Openssl
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
