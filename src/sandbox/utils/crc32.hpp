#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace kvm {

template <uint32_t POLYNOMIAL>
inline constexpr auto gen_crc32_table()
{
	constexpr auto num_iterations = 8;
	auto crc32_table = std::array<uint32_t, 256> {};

	for (auto byte = 0u; byte < crc32_table.size(); ++byte) {
		auto crc = byte;

		for (auto i = 0; i < num_iterations; ++i) {
			auto mask = -(crc & 1);
			crc = (crc >> 1) ^ (POLYNOMIAL & mask);
		}

		crc32_table[byte] = crc;
	}
	return crc32_table;
}

template <uint32_t POLYNOMIAL = 0xEDB88320>
inline constexpr auto crc32(const char* data)
{
	constexpr auto crc32_table = gen_crc32_table<POLYNOMIAL>();

	auto crc = 0xFFFFFFFFu;
	for (auto i = 0u; auto c = data[i]; ++i) {
		crc = crc32_table[(crc ^ c) & 0xFF] ^ (crc >> 8);
	}
	return ~crc;
}

template <uint32_t POLYNOMIAL = 0xEDB88320>
inline constexpr auto crc32(const void* vdata, const size_t len)
{
	constexpr auto crc32_table = gen_crc32_table<POLYNOMIAL>();

	auto* data = (const uint8_t*) vdata;
	auto crc = 0xFFFFFFFFu;
	for (auto i = 0u; i < len; ++i) {
		crc = crc32_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
	}
	return ~crc;
}

template <uint32_t POLYNOMIAL = 0xEDB88320>
inline auto crc32(const std::string& value)
{
	return crc32<POLYNOMIAL>(value.c_str(), value.size());
}

inline auto crc32c(const std::string& value)
{
	return crc32<0x1EDC6F41>(value.c_str(), value.size());
}

extern uint32_t crc32c_hw(uint32_t partial, const char* data, size_t len);
extern uint32_t crc32c_hw(const char* data, size_t len);

inline uint32_t crc32c_hw(const std::string& value)
{
	return crc32c_hw(value.c_str(), value.size());
}

} // kvm
