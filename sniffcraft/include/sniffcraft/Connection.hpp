#pragma once

#include <functional>
#include <vector>
#include <thread>
#include <atomic>
#include <memory>
#include <deque>

#include <asio.hpp>

constexpr size_t BUFFER_SIZE = 1024;

class DataProcessor;

class Connection
{
public:
	Connection(asio::io_context& io_context);
	~Connection();

	/// @brief Setter for the callback called on data reception
	/// @param callback a function to call
	void SetCallback(const std::function<void(const size_t)>& callback);

	/// @brief Setter for the data processor
	/// @param processor The processor this connection will take ownership of
	void SetDataProcessor(std::unique_ptr<DataProcessor>& processor);

	/// @brief Get all available ready data in ready_received_data and clear the vector
	/// @param dst Vector to which the data will be pushed to
	void RetreiveData(std::vector<unsigned char>& dst);

	/// @brief Start writing/reading data to/from this socket
	void StartListeningAndWriting();

	/// @brief Push given data to the buffer to be sent through the socket
	/// @param data Pointer to the first data element
	/// @param length Size of the data in bytes
	void WriteData(const unsigned char* const data, const size_t length);

	/// @brief Getter for this connection underlying socket
	/// @return A reference to asio socket
	asio::ip::tcp::socket& GetSocket();

	/// @brief Close the underlying socket
	void Close();

	/// @brief Get the state of this connection
	/// @return True if closed, false otherwise 
	bool Closed() const;

private:
	void WriteLoop();
	void handle_read(const asio::error_code& ec, const size_t bytes_transferred);
	void handle_timeout(const asio::error_code& ec);

private:
	std::atomic<bool> closed;
	/// @brief Function called when N new bytes were added in ready_received_data
	std::function<void(const size_t)> data_callback;

	/// @brief Connection underlying socket
	asio::ip::tcp::socket socket;
	asio::steady_timer timeout_timer;

	/// @brief BUFFER_SIZE vector used to store incoming bytes
	std::vector<unsigned char> read_buffer;
	/// @brief Growing buffer storing all the received bytes ready to be processed. Protected by received_mutex
	std::vector<unsigned char> ready_received_data;
	/// @brief mutex protecting ready_received_data
	std::mutex received_mutex;

	/// @brief Thread running the sync writing loop
	std::thread write_thread;
	std::atomic<bool> write_thread_started;
	/// @brief A deque of data to send. If second parameter bool is set to true, means that we need to apply data_processor to it before sending
	std::deque<std::pair<std::vector<unsigned char>, bool>> data_to_write;
	/// @brief mutex protecting data_to_write
	std::mutex write_mutex;
	/// @brief condition variable notified when a new data is added to data_to_write
	std::condition_variable write_cv;

	/// @brief Optional DataProcessor applied to all incoming and outgoing data
	std::unique_ptr<DataProcessor> data_processor;
};
