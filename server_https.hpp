#ifndef SERVER_HTTPS_HPP
#define SERVER_HTTPS_HPP

#include "server_http.hpp"

#ifdef USE_STANDALONE_ASIO
#include <asio/ssl.hpp>
#else
#include <boost/asio/ssl.hpp>
#endif

#include <algorithm>
#include <openssl/ssl.h>

namespace SimpleWeb {
  using HTTPS = asio::ssl::stream<asio::ip::tcp::socket>;

  template <>
  class Server<HTTPS> : public ServerBase<HTTPS> {
    bool set_session_id_context = false;

  public:
    Server(const std::string &cert_file, const std::string &private_key_file, const std::string &verify_file = std::string(), const std::string& dh_file = std::string(), const std::string& cipher_list = std::string())
        : ServerBase<HTTPS>::ServerBase(443), context(asio::ssl::context::sslv23) {

      context.set_options(asio::ssl::context::no_sslv2 | asio::ssl::context::no_sslv3);
      context.use_certificate_file(cert_file, asio::ssl::context::pem);
      context.use_private_key_file(private_key_file, asio::ssl::context::pem);

      if(verify_file.size() > 0) {
        context.load_verify_file(verify_file);
        //context.set_verify_mode(asio::ssl::verify_peer | asio::ssl::verify_fail_if_no_peer_cert | asio::ssl::verify_client_once);
        set_session_id_context = true;
      }

      if (dh_file.size() > 0) {
        context.use_tmp_dh_file(dh_file);
        SSL_CTX_set_options(context.native_handle(), SSL_OP_SINGLE_DH_USE);
      }

      EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
      if (ecdh != NULL) /* error */
        SSL_CTX_set_tmp_ecdh(context.native_handle(), ecdh);
      EC_KEY_free(ecdh); /* Safe because of reference counts */

      //set custom cipher list
      if (cipher_list.size() > 0) {
        SSL_CTX_set_cipher_list(context.native_handle(), cipher_list.c_str());
        SSL_CTX_set_options(context.native_handle(), SSL_OP_CIPHER_SERVER_PREFERENCE);
      }

    }

  protected:
    asio::ssl::context context;

    void after_bind() override {
      if(set_session_id_context) {
        // Creating session_id_context from address:port but reversed due to small SSL_MAX_SSL_SESSION_ID_LENGTH
        auto session_id_context = std::to_string(acceptor->local_endpoint().port()) + ':';
        session_id_context.append(config.address.rbegin(), config.address.rend());
        SSL_CTX_set_session_id_context(context.native_handle(), reinterpret_cast<const unsigned char *>(session_id_context.data()),
                                       std::min<std::size_t>(session_id_context.size(), SSL_MAX_SSL_SESSION_ID_LENGTH));
      }
    }

    void accept() override {
      auto connection = create_connection(*io_service, context);

      acceptor->async_accept(connection->socket->lowest_layer(), [this, connection](const error_code &ec) {
        auto lock = connection->handler_runner->continue_lock();
        if(!lock)
          return;

        if(ec != asio::error::operation_aborted)
          this->accept();

        auto session = std::make_shared<Session>(config.max_request_streambuf_size, connection);

        if(!ec) {
          asio::ip::tcp::no_delay option(true);
          error_code ec;
          session->connection->socket->lowest_layer().set_option(option, ec);

          session->connection->set_timeout(config.timeout_request);
          session->connection->socket->async_handshake(asio::ssl::stream_base::server, [this, session](const error_code &ec) {
            session->connection->cancel_timeout();
            auto lock = session->connection->handler_runner->continue_lock();
            if(!lock)
              return;
            if(!ec)
              this->read(session);
            else if(this->on_error)
              this->on_error(session->request, ec);
          });
        }
        else if(this->on_error)
          this->on_error(session->request, ec);
      });
    }
  };
} // namespace SimpleWeb

#endif /* SERVER_HTTPS_HPP */
