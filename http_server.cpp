#include "common/xlogger.hpp"
#include "http_server.h"

namespace http
{
	namespace server
	{
		namespace mime_types
		{

			struct mapping
			{
				const char* extension;
				const char* mime_type;
			} mappings[] =
			{
			  { "gif", "image/gif" },
			  { "htm", "text/html" },
			  { "html", "text/html" },
			  { "jpg", "image/jpeg" },
			  { "png", "image/png" }
			};

			std::string extension_to_type(const std::string& extension)
			{
				for (mapping m : mappings)
				{
					if (m.extension == extension)
					{
						return m.mime_type;
					}
				}

				return "text/plain";
			}

		} // namespace mime_types


		namespace status_strings
		{

			const std::string ok =
				"HTTP/1.0 200 OK\r\n";
			const std::string created =
				"HTTP/1.0 201 Created\r\n";
			const std::string accepted =
				"HTTP/1.0 202 Accepted\r\n";
			const std::string no_content =
				"HTTP/1.0 204 No Content\r\n";
			const std::string multiple_choices =
				"HTTP/1.0 300 Multiple Choices\r\n";
			const std::string moved_permanently =
				"HTTP/1.0 301 Moved Permanently\r\n";
			const std::string moved_temporarily =
				"HTTP/1.0 302 Moved Temporarily\r\n";
			const std::string not_modified =
				"HTTP/1.0 304 Not Modified\r\n";
			const std::string bad_request =
				"HTTP/1.0 400 Bad Request\r\n";
			const std::string unauthorized =
				"HTTP/1.0 401 Unauthorized\r\n";
			const std::string forbidden =
				"HTTP/1.0 403 Forbidden\r\n";
			const std::string not_found =
				"HTTP/1.0 404 Not Found\r\n";
			const std::string internal_server_error =
				"HTTP/1.0 500 Internal Server Error\r\n";
			const std::string not_implemented =
				"HTTP/1.0 501 Not Implemented\r\n";
			const std::string bad_gateway =
				"HTTP/1.0 502 Bad Gateway\r\n";
			const std::string service_unavailable =
				"HTTP/1.0 503 Service Unavailable\r\n";

			asio::const_buffer to_buffer(HttpReply::status_type status)
			{
				switch (status)
				{
				case HttpReply::ok:
					return asio::buffer(ok);
				case HttpReply::created:
					return asio::buffer(created);
				case HttpReply::accepted:
					return asio::buffer(accepted);
				case HttpReply::no_content:
					return asio::buffer(no_content);
				case HttpReply::multiple_choices:
					return asio::buffer(multiple_choices);
				case HttpReply::moved_permanently:
					return asio::buffer(moved_permanently);
				case HttpReply::moved_temporarily:
					return asio::buffer(moved_temporarily);
				case HttpReply::not_modified:
					return asio::buffer(not_modified);
				case HttpReply::bad_request:
					return asio::buffer(bad_request);
				case HttpReply::unauthorized:
					return asio::buffer(unauthorized);
				case HttpReply::forbidden:
					return asio::buffer(forbidden);
				case HttpReply::not_found:
					return asio::buffer(not_found);
				case HttpReply::internal_server_error:
					return asio::buffer(internal_server_error);
				case HttpReply::not_implemented:
					return asio::buffer(not_implemented);
				case HttpReply::bad_gateway:
					return asio::buffer(bad_gateway);
				case HttpReply::service_unavailable:
					return asio::buffer(service_unavailable);
				default:
					return asio::buffer(internal_server_error);
				}
			}

		} // namespace status_strings

		namespace misc_strings
		{

			const char name_value_separator[] = { ':', ' ' };
			const char crlf[] = { '\r', '\n' };

		} // namespace misc_strings

		std::vector<asio::const_buffer> HttpReply::to_buffers()
		{
			std::vector<asio::const_buffer> buffers;
			buffers.push_back(status_strings::to_buffer(status));
			for (std::size_t i = 0; i < headers.size(); ++i)
			{
				HttpHeader& h = headers[i];
				buffers.push_back(asio::buffer(h.name));
				buffers.push_back(asio::buffer(misc_strings::name_value_separator));
				buffers.push_back(asio::buffer(h.value));
				buffers.push_back(asio::buffer(misc_strings::crlf));
			}
			buffers.push_back(asio::buffer(misc_strings::crlf));
			buffers.push_back(asio::buffer(content));
			return buffers;
		}

		namespace routine_replies
		{

			const char ok[] = "";
			const char created[] =
				"<html>"
				"<head><title>Created</title></head>"
				"<body><h1>201 Created</h1></body>"
				"</html>";
			const char accepted[] =
				"<html>"
				"<head><title>Accepted</title></head>"
				"<body><h1>202 Accepted</h1></body>"
				"</html>";
			const char no_content[] =
				"<html>"
				"<head><title>No Content</title></head>"
				"<body><h1>204 Content</h1></body>"
				"</html>";
			const char multiple_choices[] =
				"<html>"
				"<head><title>Multiple Choices</title></head>"
				"<body><h1>300 Multiple Choices</h1></body>"
				"</html>";
			const char moved_permanently[] =
				"<html>"
				"<head><title>Moved Permanently</title></head>"
				"<body><h1>301 Moved Permanently</h1></body>"
				"</html>";
			const char moved_temporarily[] =
				"<html>"
				"<head><title>Moved Temporarily</title></head>"
				"<body><h1>302 Moved Temporarily</h1></body>"
				"</html>";
			const char not_modified[] =
				"<html>"
				"<head><title>Not Modified</title></head>"
				"<body><h1>304 Not Modified</h1></body>"
				"</html>";
			const char bad_request[] =
				"<html>"
				"<head><title>Bad Request</title></head>"
				"<body><h1>400 Bad Request</h1></body>"
				"</html>";
			const char unauthorized[] =
				"<html>"
				"<head><title>Unauthorized</title></head>"
				"<body><h1>401 Unauthorized</h1></body>"
				"</html>";
			const char forbidden[] =
				"<html>"
				"<head><title>Forbidden</title></head>"
				"<body><h1>403 Forbidden</h1></body>"
				"</html>";
			const char not_found[] =
				"<html>"
				"<head><title>Not Found</title></head>"
				"<body><h1>404 Not Found</h1></body>"
				"</html>";
			const char internal_server_error[] =
				"<html>"
				"<head><title>Internal Server Error</title></head>"
				"<body><h1>500 Internal Server Error</h1></body>"
				"</html>";
			const char not_implemented[] =
				"<html>"
				"<head><title>Not Implemented</title></head>"
				"<body><h1>501 Not Implemented</h1></body>"
				"</html>";
			const char bad_gateway[] =
				"<html>"
				"<head><title>Bad Gateway</title></head>"
				"<body><h1>502 Bad Gateway</h1></body>"
				"</html>";
			const char service_unavailable[] =
				"<html>"
				"<head><title>Service Unavailable</title></head>"
				"<body><h1>503 Service Unavailable</h1></body>"
				"</html>";

			std::string to_string(HttpReply::status_type status)
			{
				switch (status)
				{
				case HttpReply::ok:
					return ok;
				case HttpReply::created:
					return created;
				case HttpReply::accepted:
					return accepted;
				case HttpReply::no_content:
					return no_content;
				case HttpReply::multiple_choices:
					return multiple_choices;
				case HttpReply::moved_permanently:
					return moved_permanently;
				case HttpReply::moved_temporarily:
					return moved_temporarily;
				case HttpReply::not_modified:
					return not_modified;
				case HttpReply::bad_request:
					return bad_request;
				case HttpReply::unauthorized:
					return unauthorized;
				case HttpReply::forbidden:
					return forbidden;
				case HttpReply::not_found:
					return not_found;
				case HttpReply::internal_server_error:
					return internal_server_error;
				case HttpReply::not_implemented:
					return not_implemented;
				case HttpReply::bad_gateway:
					return bad_gateway;
				case HttpReply::service_unavailable:
					return service_unavailable;
				default:
					return internal_server_error;
				}
			}

		} // namespace routine_replies

		HttpReply HttpReply::routine_reply(HttpReply::status_type status)
		{
			HttpReply rep;
			rep.status = status;
			rep.content = routine_replies::to_string(status);
			rep.headers.resize(2);
			rep.headers[0].name = "Content-Length";
			rep.headers[0].value = std::to_string(rep.content.size());
			rep.headers[1].name = "Content-Type";
			rep.headers[1].value = mime_types::extension_to_type("json");
			return rep;
		}

		HttpRequestParser::HttpRequestParser()
			: state_(method_start)
		{}

		void HttpRequestParser::reset()
		{
			state_ = method_start;
		}

		HttpRequestParser::result_type HttpRequestParser::consume(HttpRequest& req, char input)
		{
			switch (state_)
			{
			case method_start:
				if (!is_char(input) || is_ctl(input) || is_tspecial(input))
				{
					return bad;
				}
				else
				{
					state_ = method;
					req.method.push_back(input);
					return indeterminate;
				}
			case method:
				if (input == ' ')
				{
					state_ = uri;
					return indeterminate;
				}
				else if (!is_char(input) || is_ctl(input) || is_tspecial(input))
				{
					return bad;
				}
				else
				{
					req.method.push_back(input);
					return indeterminate;
				}
			case uri:
				if (input == ' ')
				{
					state_ = http_version_h;
					return indeterminate;
				}
				else if (is_ctl(input))
				{
					return bad;
				}
				else
				{
					req.uri.push_back(input);
					return indeterminate;
				}
			case http_version_h:
				if (input == 'H')
				{
					state_ = http_version_t_1;
					return indeterminate;
				}
				else
				{
					return bad;
				}
			case http_version_t_1:
				if (input == 'T')
				{
					state_ = http_version_t_2;
					return indeterminate;
				}
				else
				{
					return bad;
				}
			case http_version_t_2:
				if (input == 'T')
				{
					state_ = http_version_p;
					return indeterminate;
				}
				else
				{
					return bad;
				}
			case http_version_p:
				if (input == 'P')
				{
					state_ = http_version_slash;
					return indeterminate;
				}
				else
				{
					return bad;
				}
			case http_version_slash:
				if (input == '/')
				{
					req.http_version_major = 0;
					req.http_version_minor = 0;
					state_ = http_version_major_start;
					return indeterminate;
				}
				else
				{
					return bad;
				}
			case http_version_major_start:
				if (is_digit(input))
				{
					req.http_version_major = req.http_version_major * 10 + input - '0';
					state_ = http_version_major;
					return indeterminate;
				}
				else
				{
					return bad;
				}
			case http_version_major:
				if (input == '.')
				{
					state_ = http_version_minor_start;
					return indeterminate;
				}
				else if (is_digit(input))
				{
					req.http_version_major = req.http_version_major * 10 + input - '0';
					return indeterminate;
				}
				else
				{
					return bad;
				}
			case http_version_minor_start:
				if (is_digit(input))
				{
					req.http_version_minor = req.http_version_minor * 10 + input - '0';
					state_ = http_version_minor;
					return indeterminate;
				}
				else
				{
					return bad;
				}
			case http_version_minor:
				if (input == '\r')
				{
					state_ = expecting_newline_1;
					return indeterminate;
				}
				else if (is_digit(input))
				{
					req.http_version_minor = req.http_version_minor * 10 + input - '0';
					return indeterminate;
				}
				else
				{
					return bad;
				}
			case expecting_newline_1:
				if (input == '\n')
				{
					state_ = header_line_start;
					return indeterminate;
				}
				else
				{
					return bad;
				}
			case header_line_start:
				if (input == '\r')
				{
					state_ = expecting_newline_3;
					return indeterminate;
				}
				else if (!req.headers.empty() && (input == ' ' || input == '\t'))
				{
					state_ = header_lws;
					return indeterminate;
				}
				else if (!is_char(input) || is_ctl(input) || is_tspecial(input))
				{
					return bad;
				}
				else
				{
					req.headers.push_back(HttpHeader());
					req.headers.back().name.push_back(input);
					state_ = header_name;
					return indeterminate;
				}
			case header_lws:
				if (input == '\r')
				{
					state_ = expecting_newline_2;
					return indeterminate;
				}
				else if (input == ' ' || input == '\t')
				{
					return indeterminate;
				}
				else if (is_ctl(input))
				{
					return bad;
				}
				else
				{
					state_ = header_value;
					req.headers.back().value.push_back(input);
					return indeterminate;
				}
			case header_name:
				if (input == ':')
				{
					state_ = space_before_header_value;
					return indeterminate;
				}
				else if (!is_char(input) || is_ctl(input) || is_tspecial(input))
				{
					return bad;
				}
				else
				{
					req.headers.back().name.push_back(input);
					return indeterminate;
				}
			case space_before_header_value:
				if (input == ' ')
				{
					state_ = header_value;
					return indeterminate;
				}
				else
				{
					return bad;
				}
			case header_value:
				if (input == '\r')
				{
					state_ = expecting_newline_2;
					return indeterminate;
				}
				else if (is_ctl(input))
				{
					return bad;
				}
				else
				{
					req.headers.back().value.push_back(input);
					return indeterminate;
				}
			case expecting_newline_2:
				if (input == '\n')
				{
					state_ = header_line_start;
					return indeterminate;
				}
				else
				{
					return bad;
				}
			case expecting_newline_3:
				return (input == '\n') ? good : bad;
			default:
				return bad;
			}
		}

		bool HttpRequestParser::is_char(int c)
		{
			return c >= 0 && c <= 127;
		}

		bool HttpRequestParser::is_ctl(int c)
		{
			return (c >= 0 && c <= 31) || (c == 127);
		}

		bool HttpRequestParser::is_tspecial(int c)
		{
			switch (c)
			{
			case '(': case ')': case '<': case '>': case '@':
			case ',': case ';': case ':': case '\\': case '"':
			case '/': case '[': case ']': case '?': case '=':
			case '{': case '}': case ' ': case '\t':
				return true;
			default:
				return false;
			}
		}

		bool HttpRequestParser::is_digit(int c)
		{
			return c >= '0' && c <= '9';
		}

		HttpServerCallback::HttpServerCallback()
		{}

		void HttpServerCallback::handle_request(const HttpRequest& req, HttpReply& rep)
		{
		}

		void HttpServerCallback::compose_response(HttpReply& rep, HttpReply::status_type status, std::string& rsp)
		{
			rep.status = status;
			rep.content = rsp;

			rep.headers.resize(2);
			rep.headers[0].name = "Content-Length";
			rep.headers[0].value = std::to_string(rep.content.size());
			rep.headers[1].name = "Content-Type";
			rep.headers[1].value = mime_types::extension_to_type("json");
		}

		bool HttpServerCallback::url_decode(const std::string& in, std::string& out)
		{
			out.clear();
			out.reserve(in.size());
			for (std::size_t i = 0; i < in.size(); ++i)
			{
				if (in[i] == '%')
				{
					if (i + 3 <= in.size())
					{
						int value = 0;
						std::istringstream is(in.substr(i + 1, 2));
						if (is >> std::hex >> value)
						{
							out += static_cast<char>(value);
							i += 2;
						}
						else
						{
							return false;
						}
					}
					else
					{
						return false;
					}
				}
				else if (in[i] == '+')
				{
					out += ' ';
				}
				else
				{
					out += in[i];
				}
			}
			return true;
		}

		HttpConnectionManager::HttpConnectionManager()
		{}

		void HttpConnectionManager::start(connection_ptr c)
		{
			connections_.insert(c);
			c->start();
		}

		void HttpConnectionManager::stop(connection_ptr c)
		{
			connections_.erase(c);
			c->stop();
		}

		void HttpConnectionManager::stop_all()
		{
			for (auto c : connections_)
				c->stop();
			connections_.clear();
		}

		HttpConnection::HttpConnection(asio::ip::tcp::socket socket,
			HttpConnectionManager& manager, HttpServerCallback* handler)
			: socket_(std::move(socket)),
			connection_manager_(manager),
			request_handler_(handler)
		{}

		void HttpConnection::start()
		{
			// init the header parse flag
			is_header_parsed_ = false;

			do_read();
		}

		void HttpConnection::stop()
		{
			socket_.close();
		}

		void HttpConnection::do_read()
		{
			auto self(shared_from_this());
			socket_.async_read_some(asio::buffer(buffer_),
				[this, self](std::error_code ec, std::size_t bytes_transferred)
				{
					if (!ec)
					{
						// POST will request twice
						std::string buf_data(buffer_.data(), bytes_transferred);
						req_data_.append(buf_data);

						// read again if encounter post
						int header_end = req_data_.find("\r\n\r\n"); // http header end mark
						if (header_end < 0)
						{
							do_read();
							return;
						}

						HttpRequestParser::result_type result;

						// parse header data
						if (!is_header_parsed_)
						{
							// this will be enough for GET request
							std::tie(result, std::ignore) = request_parser_.parse(
								request_, buffer_.data(), buffer_.data() + bytes_transferred);
						}

						if (is_header_parsed_ || result == HttpRequestParser::good)
						{
							is_header_parsed_ = true; // set true anyway after parse header success
							
							std::string length_str;
							for (int i = 0; i < request_.headers.size(); i++)
							{
								if (request_.headers[i].name == "Content-Length")
								{
									length_str = request_.headers[i].value;
									break;
								}
							}

							int content_length = 0;
							if (!length_str.empty())
								content_length = atoi(length_str.c_str());

							if (req_data_.length() < (content_length + header_end + 4)) // FIXME: 4 stands for \r\n\r\n
							{
								// read data incomplete, continue to read
								do_read();
								return;
							}

							// parse body data in the tail if needed, here support string format body data
							request_.body = req_data_.substr(header_end + 4); // FIXME: 4 stands for \r\n\r\n
							
							// clear the temp buffer before handle
							req_data_.clear();
							request_handler_->handle_request(request_, reply_);

							// response
							do_write();
						}
						else if (result == HttpRequestParser::bad)
						{
							reply_ = HttpReply::routine_reply(HttpReply::bad_request);
							do_write();
						}
						else
						{
							do_read();
						}
					}
					else if (ec != asio::error::operation_aborted)
					{
						connection_manager_.stop(shared_from_this());
					}
				});
		}

		void HttpConnection::do_write()
		{
			auto self(shared_from_this());
			asio::async_write(socket_, reply_.to_buffers(),
				[this, self](std::error_code ec, std::size_t)
				{
					if (!ec)
					{
						// Initiate graceful connection closure.
						asio::error_code ignored_ec;
						socket_.shutdown(asio::ip::tcp::socket::shutdown_both,
							ignored_ec);
					}

					if (ec != asio::error::operation_aborted)
					{
						connection_manager_.stop(shared_from_this());
					}
				});
		}


		HttpServer::HttpServer(int port):
			io_context_(1),
			signals_(io_context_),
			acceptor_(io_context_),
			connection_manager_()
		{
			m_port = port;

			// Open the acceptor with the option to reuse the address (i.e. SO_REUSEADDR).
			asio::ip::tcp::resolver resolver(io_context_);

			asio::ip::tcp::endpoint endpoint = *resolver.resolve("0.0.0.0", std::to_string(m_port)).begin();
			acceptor_.open(endpoint.protocol());
			acceptor_.set_option(asio::ip::tcp::acceptor::reuse_address(true));
			acceptor_.bind(endpoint);
			acceptor_.listen();

			do_accept();
		}

		HttpServer::~HttpServer()
		{
			m_main_thread.join();
		}

		void HttpServer::start()
		{
			// start http server in independent thread
			m_main_thread = std::thread([&]
				{
					// The io_context::run() call will block until all asynchronous operations
					// have finished. While the server is running, there is always at least one
					// asynchronous operation outstanding: the asynchronous accept call waiting
					// for new incoming connections.
					io_context_.run();
				});
			XLOG_INFO("HttpServer http server is listening at port: {}", m_port);
		}

		void HttpServer::stop()
		{
			acceptor_.close();
			connection_manager_.stop_all();
			io_context_.stop();
		}

		void HttpServer::set_request_handler(HttpServerCallback* req_handler)
		{
			// acually set outside inherited handler
			request_handler_ = req_handler;
		}

		void HttpServer::do_accept()
		{
			acceptor_.async_accept(
				[this](std::error_code ec, asio::ip::tcp::socket socket)
				{
					// Check whether the server was stopped before this
					// completion handler had a chance to run.
					if (!acceptor_.is_open())
					{
						return;
					}

					if (!ec)
					{
						connection_manager_.start(std::make_shared<HttpConnection>(
							std::move(socket), connection_manager_, request_handler_));
					}

					do_accept();
				});
		}

	} // namespace server
} // namespace http
