
include(FetchContent)
FetchContent_Declare(
  concurrentqueue
  GIT_REPOSITORY    https://github.com/cameron314/concurrentqueue
  GIT_TAG           master
)
FetchContent_MakeAvailable(concurrentqueue)

add_subdirectory(ext/tinykvm/lib tinykvm)
add_subdirectory(ext/json json)

add_library(kvm
	archive.cpp
	curl_fetch.cpp
    kvm_settings.cpp
    kvm_stats.cpp
    live_update.cpp
    machine_debug.cpp
    machine_instance.cpp
    program_instance.cpp
    tenant.cpp
    tenant_instance.cpp
	server/epoll.cpp
    system_calls.cpp
    utils/crc32.cpp
)

target_link_libraries(kvm PUBLIC tinykvm numa concurrentqueue archive curl nlohmann_json)
