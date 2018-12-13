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

/*void OpensslSocket::doHandshakeNext() {
  ENVOY_CONN_LOG(debug, "TSI: doHandshake next: received: {}", callbacks_->connection(),
                 raw_read_buffer_.length());

  if (!handshaker_) {
    handshaker_ = handshaker_factory_(callbacks_->connection().dispatcher(),
                                      callbacks_->connection().localAddress(),
                                      callbacks_->connection().remoteAddress());
    if (!handshaker_) {
      ENVOY_CONN_LOG(warn, "TSI: failed to create handshaker", callbacks_->connection());
      callbacks_->connection().close(Network::ConnectionCloseType::NoFlush);
      return;
    }

    handshaker_->setHandshakerCallbacks(*this);
  }

  handshaker_next_calling_ = true;
  Buffer::OwnedImpl handshaker_buffer;
  handshaker_buffer.move(raw_read_buffer_);
  handshaker_->next(handshaker_buffer);
}*/

/*Network::PostIoAction OpensslSocket::doHandshakeNextDone(NextResultPtr&& next_result) {
  ASSERT(next_result);

  ENVOY_CONN_LOG(debug, "TSI: doHandshake next done: status: {} to_send: {}",
                 callbacks_->connection(), next_result->status_, next_result->to_send_->length());

  tsi_result status = next_result->status_;
  tsi_handshaker_result* handshaker_result = next_result->result_.get();

  if (status != TSI_INCOMPLETE_DATA && status != TSI_OK) {
    ENVOY_CONN_LOG(debug, "TSI: Handshake failed: status: {}", callbacks_->connection(), status);
    return Network::PostIoAction::Close;
  }

  if (next_result->to_send_->length() > 0) {
    raw_write_buffer_.move(*next_result->to_send_);
  }

  if (status == TSI_OK && handshaker_result != nullptr) {
    tsi_peer peer;
    // returns TSI_OK assuming there is no fatal error. Asserting OK.
    status = tsi_handshaker_result_extract_peer(handshaker_result, &peer);
    ASSERT(status == TSI_OK);
    Cleanup peer_cleanup([&peer]() { tsi_peer_destruct(&peer); });
    ENVOY_CONN_LOG(debug, "TSI: Handshake successful: peer properties: {}",
                   callbacks_->connection(), peer.property_count);
    for (size_t i = 0; i < peer.property_count; ++i) {
      ENVOY_CONN_LOG(debug, "  {}: {}", callbacks_->connection(), peer.properties[i].name,
                     std::string(peer.properties[i].value.data, peer.properties[i].value.length));
    }
    if (handshake_validator_) {
      std::string err;
      const bool peer_validated = handshake_validator_(peer, err);
      if (peer_validated) {
        ENVOY_CONN_LOG(debug, "TSI: Handshake validation succeeded.", callbacks_->connection());
      } else {
        ENVOY_CONN_LOG(debug, "TSI: Handshake validation failed: {}", callbacks_->connection(),
                       err);
        return Network::PostIoAction::Close;
      }
    } else {
      ENVOY_CONN_LOG(debug, "TSI: Handshake validation skipped.", callbacks_->connection());
    }

    const unsigned char* unused_bytes;
    size_t unused_byte_size;

    // returns TSI_OK assuming there is no fatal error. Asserting OK.
    status =
        tsi_handshaker_result_get_unused_bytes(handshaker_result, &unused_bytes, &unused_byte_size);
    ASSERT(status == TSI_OK);
    if (unused_byte_size > 0) {
      raw_read_buffer_.prepend(
          absl::string_view{reinterpret_cast<const char*>(unused_bytes), unused_byte_size});
    }
    ENVOY_CONN_LOG(debug, "TSI: Handshake successful: unused_bytes: {}", callbacks_->connection(),
                   unused_byte_size);

    // returns TSI_OK assuming there is no fatal error. Asserting OK.
    tsi_frame_protector* frame_protector;
    status =
        tsi_handshaker_result_create_frame_protector(handshaker_result, NULL, &frame_protector);
    ASSERT(status == TSI_OK);
    frame_protector_ = std::make_unique<OpensslFrameProtector>(frame_protector);

    handshake_complete_ = true;
    callbacks_->raiseEvent(Network::ConnectionEvent::Connected);
  }

  if (read_error_ || (!handshake_complete_ && end_stream_read_)) {
    ENVOY_CONN_LOG(debug, "TSI: Handshake failed: end of stream without enough data",
                   callbacks_->connection());
    return Network::PostIoAction::Close;
  }

  if (raw_read_buffer_.length() > 0) {
    callbacks_->setReadBufferReady();
  }

  // Try to write raw buffer when next call is done, even this is not in do[Read|Write] stack.
  if (raw_write_buffer_.length() > 0) {
    return raw_buffer_socket_->doWrite(raw_write_buffer_, false).action_;
  }

  return Network::PostIoAction::KeepOpen;
}*/

Network::IoResult OpensslSocket::doRead(Buffer::Instance& read_buffer) {
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

/*void OpensslSocket::onNextDone(NextResultPtr&& result) {
  handshaker_next_calling_ = false;

  Network::PostIoAction action = doHandshakeNextDone(std::move(result));
  if (action == Network::PostIoAction::Close) {
    callbacks_->connection().close(Network::ConnectionCloseType::NoFlush);
  }
}*/

OpensslSocketFactory::OpensslSocketFactory(){}

bool OpensslSocketFactory::implementsSecureTransport() const { return true; }

Network::TransportSocketPtr
OpensslSocketFactory::createTransportSocket(Network::TransportSocketOptionsSharedPtr) const {
  return std::make_unique<OpensslSocket>();
}

} // namespace Openssl
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
