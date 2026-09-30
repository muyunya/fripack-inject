#include "config.h"
#include "logger.h"

#include <lzma.h>
#include <rfl.hpp>
#include <rfl/json.hpp>


namespace fripack::config {

void print_hexdump(const uint8_t *data, size_t size) {
  constexpr size_t bytes_per_line = 16;
  std::string res;
  for (size_t i = 0; i < size; i += bytes_per_line) {
    res += fmt::format("{:08x}  ", i);
    for (size_t j = 0; j < bytes_per_line; ++j) {
      if (i + j < size) {
        res += fmt::format("{:02x} ", data[i + j]);
      } else {
        res += "   ";
      }
      if (j == 7) {
        res += " ";
      }
    }
    res += " |";
    for (size_t j = 0; j < bytes_per_line; ++j) {
      if (i + j < size) {
        char c = data[i + j];
        res += (c >= 32 && c <= 126) ? c : '.';
      } else {
        res += ' ';
      }
    }
    res += "|\n";
  }

  logger::println("\n{}", res);
}

#pragma pack(push, 1)
struct EmbeddedConfig {
  int32_t magic1 = 0x0d000721;
  int32_t magic2 = 0x1f8a4e2b;
  int32_t version = 1;

  int32_t data_size = 0;
  int32_t data_offset = 0; // Offset from the start of the struct.
  bool data_xz = false;    // Whether the data is compressed with xz.
};
#pragma pack(pop)

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __attribute__((visibility("default")))
#endif

EXPORT EmbeddedConfig g_embedded_config{};

#ifdef __APPLE__
// Reserved, file-backed buffer that fripack writes the embedded script into.
//
// Mach-O payloads are patched in place rather than rewritten, so the buffer has
// to exist in the file up front: fripack locates it by section name and fills in
// `data_size` / `data_offset`. Two invariants matter:
//   * the initialiser is load-bearing. Drop it and the linker folds the buffer
//     into zerofill, which occupies no space in the file and cannot be patched.
//   * it must land in the same segment as g_embedded_config (__DATA), because
//     `data_offset` is a virtual-address delta between the two.
// ELF and PE do not need it: fripack appends a section to those instead.
#ifndef FRIPACK_RESERVE
#define FRIPACK_RESERVE (1024 * 1024)
#endif

EXPORT __attribute__((used, section("__DATA,__fripack")))
unsigned char g_fripack_payload[FRIPACK_RESERVE] = {0};
#endif

const EmbeddedConfigData &configData() {
  static std::optional<EmbeddedConfigData> config_data;

  if (!config_data) {
    if (g_embedded_config.magic1 != 0x0d000721 ||
        g_embedded_config.magic2 != 0x1f8a4e2b ||
        g_embedded_config.version != 1) {
      logger::println("Invalid embedded config");
      print_hexdump(reinterpret_cast<const uint8_t *>(&g_embedded_config),
                    sizeof(g_embedded_config));
      throw std::runtime_error("Invalid embedded config");
    }

    std::vector<char> data(g_embedded_config.data_size);
    char *p_embedded_config_data =
        reinterpret_cast<char *>(&g_embedded_config) +
        g_embedded_config.data_offset;
    std::memcpy(data.data(), p_embedded_config_data,
                g_embedded_config.data_size);

    if (g_embedded_config.data_xz) {
      lzma_stream strm = LZMA_STREAM_INIT;

      lzma_ret ret = lzma_stream_decoder(&strm, UINT64_MAX, LZMA_CONCATENATED);
      if (ret != LZMA_OK) {
        logger::println("Failed to initialize LZMA decoder: {}",
                        rfl::enum_to_string(ret));
        lzma_end(&strm);
        throw std::runtime_error("Failed to initialize LZMA decoder");
      }

      strm.next_in = reinterpret_cast<const uint8_t *>(data.data());
      strm.avail_in = data.size();

      std::vector<char> decompressed_data{};
      constexpr size_t chunk_size = 64 * 1024;
      constexpr size_t max_size = 300 * 1024 * 1024;

      while (true) {
        std::vector<char> chunk(chunk_size);
        strm.next_out = reinterpret_cast<uint8_t *>(chunk.data());
        strm.avail_out = chunk.size();

        ret = lzma_code(&strm, LZMA_FINISH);

        size_t decompressed_chunk_size = chunk.size() - strm.avail_out;
        if (decompressed_data.size() + decompressed_chunk_size > max_size) {
          logger::println("Decompressed data too large (> {} MB)",
                          max_size / (1024 * 1024));
          lzma_end(&strm);
          throw std::runtime_error("Decompressed data too large");
        }

        decompressed_data.insert(decompressed_data.end(), chunk.begin(),
                                 chunk.begin() + decompressed_chunk_size);

        if (ret == LZMA_STREAM_END || strm.avail_in == 0) {
          break;
        } else if (ret != LZMA_OK) {
          logger::println("LZMA decompression failed: {}",
                          rfl::enum_to_string(ret));
          lzma_end(&strm);
          throw std::runtime_error("LZMA decompression failed");
        }
      }

      lzma_end(&strm);
      data = std::move(decompressed_data);
    }

    auto json_str = std::string(data.data(), data.size());

    if (auto res = rfl::json::read<EmbeddedConfigData>(json_str)) {
      config_data = res.value();
    } else {
      logger::println("Failed to parse embedded config data: {}",
                      res.error().what());
      logger::println("Embedded data hexdump:");
      print_hexdump(reinterpret_cast<const uint8_t *>(data.data()),
                    std::min(data.size(), static_cast<size_t>(100)));
      throw std::runtime_error("Failed to parse embedded config data");
    }
  }

  return *config_data;
}

}; // namespace fripack::config