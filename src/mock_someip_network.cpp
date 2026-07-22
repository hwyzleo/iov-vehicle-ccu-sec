#include "mock_someip_network.h"

namespace mock_someip {

// 定义线程局部变量
thread_local int Application::current_network_client_fd_ = -1;

} // namespace mock_someip
