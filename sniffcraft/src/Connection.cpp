#include "sniffcraft/Connection.hpp"
#include "sniffcraft/DataProcessor.hpp"

Connection::Connection(asio::io_context& io_context) :
    socket(io_context),
    timeout_timer(io_context)
{
    read_buffer = std::vector<unsigned char>(BUFFER_SIZE);
    closed = false;
}

Connection::~Connection()
{
    Close();
}

void Connection::SetCallback(const std::function<void(const size_t)>& callback)
{
    data_callback = callback;
}

void Connection::SetDataProcessor(std::unique_ptr<DataProcessor>& processor)
{
    // Lock mutex to prevent any race condition issue in WriteData
    std::lock_guard<std::mutex> write_lock(write_mutex);
    data_processor = std::move(processor);
}

void Connection::RetreiveData(std::vector<unsigned char>& dst)
{
    std::lock_guard<std::mutex> received_lock(received_mutex);
    dst.insert(dst.end(), ready_received_data.begin(), ready_received_data.end());
    ready_received_data.clear();
}

void Connection::StartListeningAndWriting()
{
    timeout_timer.expires_from_now(std::chrono::seconds(10));
    timeout_timer.async_wait(
        std::bind(&Connection::handle_timeout, this, std::placeholders::_1)
    );
    socket.async_read_some(asio::buffer(read_buffer.data(), BUFFER_SIZE),
        std::bind(&Connection::handle_read, this,
            std::placeholders::_1, std::placeholders::_2));
    write_thread = std::thread(&Connection::WriteLoop, this);
}

void Connection::WriteData(const unsigned char* const data, const size_t length)
{
    {
        std::lock_guard<std::mutex> write_lock(write_mutex);
        data_to_write.push_back({ std::vector<unsigned char>(data, data + length), data_processor != nullptr });
    }
    write_cv.notify_one();
}

asio::ip::tcp::socket& Connection::GetSocket()
{
    return socket;
}

void Connection::Close()
{
    closed = true;
    if (socket.is_open())
    {
        socket.close();
    }
    write_cv.notify_one();
    if (write_thread.joinable())
    {
        write_thread.join();
    }
}

bool Connection::Closed() const
{
    return closed;
}

void Connection::WriteLoop()
{
    // Run indefinitely
    while (!closed)
    {
        // Wait for some data
        {
            std::unique_lock<std::mutex> write_lock(write_mutex);
            write_cv.wait(write_lock);
        }

        if (closed)
        {
            break;
        }

        while (!data_to_write.empty())
        {
            std::pair<std::vector<unsigned char>, bool> next_written;
            {
                std::lock_guard<std::mutex> write_lock(write_mutex);
                next_written = data_to_write.front();
                data_to_write.pop_front();
            }


            const unsigned char* data_ptr = next_written.first.data();
            size_t data_length = next_written.first.size();

            std::vector<unsigned char> processed_data;
            if (next_written.second)
            {
                processed_data = data_processor->ProcessOutgoingData(next_written.first);
                data_ptr = processed_data.data();
                data_length = processed_data.size();
            }

            asio::error_code ec;
            asio::write(socket, asio::buffer(data_ptr, data_length), ec);
            if (ec)
            {
                Close();
                return;
            }
        }
    }
}

void Connection::handle_read(const asio::error_code& ec, const size_t bytes_transferred)
{
    if (closed)
    {
        return;
    }

    if (ec)
    {
        Close();
        return;
    }

    std::vector<unsigned char>& data = read_buffer;
    size_t length = bytes_transferred;

    std::vector<unsigned char> processed_data;
    if (data_processor != nullptr)
    {
        processed_data = data_processor->ProcessIncomingData({ data.begin(), data.begin() + length });
        data = processed_data;
        length = processed_data.size();
    }

    {
        std::lock_guard<std::mutex> received_lock(received_mutex);
        ready_received_data.insert(ready_received_data.end(), data.begin(), data.begin() + length);

        // We need to protect the callback call in the mutex scope
        // otherwise we could have data in the buffer without the
        // data length being transmitted correctly
        if (data_callback)
        {
            data_callback(length);
        }
    }

    timeout_timer.cancel();
    timeout_timer.expires_from_now(std::chrono::seconds(60));
    timeout_timer.async_wait(
        std::bind(&Connection::handle_timeout, this, std::placeholders::_1)
    );

    socket.async_read_some(asio::buffer(read_buffer.data(), BUFFER_SIZE),
        std::bind(&Connection::handle_read, this,
            std::placeholders::_1, std::placeholders::_2));
}

void Connection::handle_timeout(const asio::error_code& ec)
{
    if (ec == asio::error::operation_aborted)
    {
        return;
    }

    Close();
}
