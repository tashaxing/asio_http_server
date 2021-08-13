#ifndef _HTTP_SERVER_H_
#define _HTTP_SERVER_H_

#include <string>
#include <vector>
#include <tuple>
#include <map>
#include <unordered_map>
#include <set>
#include <unordered_set>
#include <memory>
#include <utility>
#include "asio.hpp"

// --- the server code is copied from asio http example
namespace http
{
	namespace server
	{
		const std::string HTTP_GET = "GET";
		const std::string HTTP_POST = "POST";

		struct HttpHeader
		{
			std::string name;
			std::string value;
		};

		namespace mime_types
		{

			/// Convert a file extension into a MIME type.
			std::string extension_to_type(const std::string& extension);

		} // namespace mime_types

		/// A request received from a client.
		struct HttpRequest
		{
			std::string method;
			std::string uri;
			int http_version_major;
			int http_version_minor;
			std::vector<HttpHeader> headers;
			std::string body; // new field
		};

		/// A reply to be sent to a client.
		struct HttpReply
		{
			/// The status of the reply.
			enum status_type
			{
				ok = 200,
				created = 201,
				accepted = 202,
				no_content = 204,
				multiple_choices = 300,
				moved_permanently = 301,
				moved_temporarily = 302,
				not_modified = 304,
				bad_request = 400,
				unauthorized = 401,
				forbidden = 403,
				not_found = 404,
				internal_server_error = 500,
				not_implemented = 501,
				bad_gateway = 502,
				service_unavailable = 503
			} status;

			/// The headers to be included in the reply.
			std::vector<HttpHeader> headers;

			/// The content to be sent in the reply.
			std::string content;

			/// Convert the reply into a vector of buffers. The buffers do not own the
			/// underlying memory blocks, therefore the reply object must remain valid and
			/// not be changed until the write operation has completed.
			std::vector<asio::const_buffer> to_buffers();

			/// Get a stock reply.
			static HttpReply routine_reply(status_type status);
		};

		/// Parser for incoming requests.
		class HttpRequestParser
		{
		public:
			/// Construct ready to parse the request method.
			HttpRequestParser();

			/// Reset to initial parser state.
			void reset();

			/// Result of parse.
			enum result_type { good, bad, indeterminate };

			/// Parse some data. The enum return value is good when a complete request has
			/// been parsed, bad if the data is invalid, indeterminate when more data is
			/// required. The InputIterator return value indicates how much of the input
			/// has been consumed.
			template <typename InputIterator>
			std::tuple<result_type, InputIterator> parse(HttpRequest& req,
				InputIterator begin, InputIterator end)
			{
				while (begin != end)
				{
					result_type result = consume(req, *begin++);
					if (result == good || result == bad)
						return std::make_tuple(result, begin);
				}
				return std::make_tuple(indeterminate, begin);
			}

		private:
			/// Handle the next character of input.
			result_type consume(HttpRequest& req, char input);

			/// Check if a byte is an HTTP character.
			static bool is_char(int c);

			/// Check if a byte is an HTTP control character.
			static bool is_ctl(int c);

			/// Check if a byte is defined as an HTTP tspecial character.
			static bool is_tspecial(int c);

			/// Check if a byte is a digit.
			static bool is_digit(int c);

			/// The current state of the parser.
			enum state
			{
				method_start,
				method,
				uri,
				http_version_h,
				http_version_t_1,
				http_version_t_2,
				http_version_p,
				http_version_slash,
				http_version_major_start,
				http_version_major,
				http_version_minor_start,
				http_version_minor,
				expecting_newline_1,
				header_line_start,
				header_lws,
				header_name,
				space_before_header_value,
				header_value,
				expecting_newline_2,
				expecting_newline_3
			} state_;
		};


		/// The common handler for all incoming requests.
		class HttpServerCallback
		{
		public:
			HttpServerCallback(const HttpServerCallback&) = delete;
			HttpServerCallback& operator=(const HttpServerCallback&) = delete;

			/// Construct with a directory containing files to be served.
			explicit HttpServerCallback();

			/// Handle a request and produce a reply.
			virtual void handle_request(const HttpRequest& req, HttpReply& rep);

		protected:
			// common method to package the json reponse as http frame
			void compose_response(HttpReply& rep, HttpReply::status_type status, std::string& rsp);
			/// Perform URL-decoding on a string. Returns false if the encoding was
			/// invalid.
			static bool url_decode(const std::string& in, std::string& out);
		};

		class HttpConnectionManager;
		/// Represents a single connection from a client.
		class HttpConnection
			: public std::enable_shared_from_this<HttpConnection>
		{
		public:
			HttpConnection(const HttpConnection&) = delete;
			HttpConnection& operator=(const HttpConnection&) = delete;

			/// Construct a connection with the given socket.
			explicit HttpConnection(asio::ip::tcp::socket socket,
				HttpConnectionManager& manager, HttpServerCallback* handler);

			/// Start the first asynchronous operation for the connection.
			void start();

			/// Stop all asynchronous operations associated with the connection.
			void stop();

		private:
			// to support POST
			bool is_header_parsed_ = false;
			std::string req_data_;

		private:
			/// Perform an asynchronous read operation.
			void do_read();

			/// Perform an asynchronous write operation.
			void do_write();

			/// Socket for the connection.
			asio::ip::tcp::socket socket_;

			/// The manager for this connection.
			HttpConnectionManager& connection_manager_;

			/// The handler used to process the incoming request.
			HttpServerCallback* request_handler_;

			/// Buffer for incoming data.
			std::array<char, 8192> buffer_;

			/// The incoming request.
			HttpRequest request_;

			/// The parser for the incoming request.
			HttpRequestParser request_parser_;

			/// The reply to be sent back to the client.
			HttpReply reply_;
		};

		typedef std::shared_ptr<HttpConnection> connection_ptr;

		/// Manages open connections so that they may be cleanly stopped when the server
/// needs to shut down.
		class HttpConnectionManager
		{
		public:
			HttpConnectionManager(const HttpConnectionManager&) = delete;
			HttpConnectionManager& operator=(const HttpConnectionManager&) = delete;

			/// Construct a connection manager.
			HttpConnectionManager();

			/// Add the specified connection to the manager and start it.
			void start(connection_ptr c);

			/// Stop the specified connection.
			void stop(connection_ptr c);

			/// Stop all connections.
			void stop_all();

		private:
			/// The managed connections.
			std::unordered_set<connection_ptr> connections_;
		};

		class HttpServer
		{
		public:
			HttpServer(const HttpServer&) = delete;
			HttpServer& operator=(const HttpServer&) = delete;

		public:
			explicit HttpServer(int port);
			virtual ~HttpServer();

			void start();
			void stop();

			void set_request_handler(HttpServerCallback* req_handler);

		private:
			/// Perform an asynchronous accept operation.
			void do_accept();

			/// Wait for a request to stop the server.
			void do_await_stop();

			/// The io_context used to perform asynchronous operations.
			asio::io_context io_context_;

			/// The signal_set is used to register for process termination notifications.
			asio::signal_set signals_;

			/// Acceptor used to listen for incoming connections.
			asio::ip::tcp::acceptor acceptor_;

			/// The connection manager which owns all live connections.
			HttpConnectionManager connection_manager_;

			/// The handler for all incoming requests.
			HttpServerCallback* request_handler_ = NULL;

		private:
			int m_port;
			std::thread m_main_thread;
		};

	} // namespace server
} // namespace http



#endif // !_HTTP_SERVER_H_
