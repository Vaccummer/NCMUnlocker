#define _WIN32_WINNT 0x0A00
#define _DISABLE_CONSTEXPR_MUTEX_CONSTRUCTOR
#include <algorithm>
#include <atomic>
#include <boost/asio/post.hpp>
#include <boost/asio/thread_pool.hpp>
#include <codecvt>
#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <fmt/core.h>
#include <fmt/format.h>
#include <fstream>
#include <functional>
#include <future>
#include <iostream>
#include <locale>
#include <mutex>
#include <nlohmann/json.hpp>
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <pybind11/functional.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <queue>
#include <string>
#include <taglib/attachedpictureframe.h>
#include <taglib/flacfile.h>
#include <taglib/id3v2tag.h>
#include <taglib/mpegfile.h>
#include <taglib/tag.h>
#include <thread>
#include <variant>
#include <vector>

enum class NCMErrorCode
{
    Success = 0,
    SrcNotExist = -1,
    SrcNotFile = -2,
    DstNotDir = -3,
    InvalidSrcFormat = -4,
    InvalidKeySize = -5,
    InvalidDataSize = -6,
    EVPContextCreationFailed = -7,
    KeyInitFailed = -8,
    AESDecryptionFailed = -9,
    InvalidCoverFormat = -10,
    InvalidMusicFormat = -11,
    OpenDstPathFailed = -12,
    OpenSrcFileFailed = -13,
    SaveFileFailed = -14,
    TaglibError = -15,
    UnknownError = -16,
    Canceled = -17,
};

class MetaParser
{
public:
    std::string music_name;
    std::string artist_name = "";
    std::string format;
    MetaParser(nlohmann::json meta)
    {
        if (meta.contains("musicName"))
        {
            this->music_name = meta["musicName"];
        }
        else
        {
            this->music_name = "unknown";
        }
        if (meta.contains("format"))
        {
            this->format = meta["format"];
        }
        else
        {
            this->format = "unknown";
        }
        if (meta.contains("artist") && meta["artist"].is_array())
        {
            auto data = meta["artist"];
            for (auto &item : data)
            {
                if (item.is_array())
                {
                    auto name = item[0];
                    // 如果name是字符串，则直接添加
                    if (name.is_string())
                    {
                        this->artist_name += name.get<std::string>() + ",";
                    }
                }
            }
        }
        if (this->artist_name.empty())
        {
            this->artist_name = "unknown";
        }
    }
};

namespace fs = std::filesystem;
namespace py = pybind11;
using EC = NCMErrorCode;
using json = nlohmann::json;
using byte = uint8_t;
using bytes = std::vector<byte>;
using bytesr = std::variant<bytes, EC>;
using Callback = std::function<void(EC, const std::string &)>;

// 字符转半字节（4位）
byte Char2Nibble(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'A' && c <= 'F')
        return 10 + (c - 'A');
    if (c >= 'a' && c <= 'f')
        return 10 + (c - 'a');
    throw std::invalid_argument("Invalid hex character: " + std::string(1, c));
}

std::vector<byte> StringKeyDecode(const std::string &hex_str)
{
    if (hex_str.length() % 2 != 0)
    {
        throw std::invalid_argument("Hex Decrypt Key String length must be even");
    }

    std::vector<byte> bytes;
    bytes.reserve(hex_str.length() / 2);

    for (size_t i = 0; i < hex_str.size(); i += 2)
    {
        byte high = Char2Nibble(hex_str[i]);
        byte low = Char2Nibble(hex_str[i + 1]);
        bytes.push_back(static_cast<byte>((high << 4) | low));
    }
    return bytes;
}

std::string RandomString(int length)
{
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                           "abcdefghijklmnopqrstuvwxyz"
                           "0123456789_"; // 包含字母和数字（共62字符）
    std::string result;
    result.reserve(length); // 预分配内存提升效率

    srand(static_cast<unsigned>(time(nullptr))); // 初始化随机种子
    for (int i = 0; i < length; ++i)
    {
        result += charset[rand() % (sizeof(charset) - 1)]; // 随机选择字符
    }
    return result;
}

std::string LegalName(const std::string &name)
{
    std::string result;
    std::vector<char> illegal_chars = {'\\', '/', ':', '*', '?', '"', '<', '>', '|'};
    for (char c : name)
    {
        if (std::find(illegal_chars.begin(), illegal_chars.end(), c) == illegal_chars.end())
        {
            result += c;
        }
        else
        {
            result += '_';
        }
    }
    return result;
}

fs::path GetUniquePath(const fs::path dst_dir, const std::string music_name, const std::string artist_name, const std::string format)
{
    std::string name_t = LegalName(music_name + "-" + artist_name + "." + format);
    fs::path final_path = dst_dir / fs::path(name_t);
    if (!fs::exists(final_path))
    {
        return final_path;
    }
    int index = 1;
    while (fs::exists(final_path))
    {
        name_t = LegalName(music_name + "-" + artist_name + "(" + std::to_string(index) + ")" + "." + format);
        final_path = dst_dir / fs::path(name_t);
        index++;
    }
    return final_path;
}

// 读取指定字节数
std::vector<byte> read_bytes(std::ifstream &file, size_t n)
{
    std::vector<byte> buffer(n);
    file.read(reinterpret_cast<char *>(buffer.data()), n);
    return buffer;
}

// 小端序读取32位整数
uint32_t read_uint32_le(std::ifstream &file)
{
    auto bytes = read_bytes(file, 4);
    return bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24);
}

// Base64解码（使用OpenSSL）
std::vector<byte> base64_decode(const std::vector<byte> &data)
{
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO *mem = BIO_new_mem_buf(data.data(), data.size());
    BIO_push(b64, mem);

    std::vector<byte> decoded(data.size());
    int len = BIO_read(b64, decoded.data(), data.size());
    decoded.resize(len);

    BIO_free_all(b64);
    return decoded;
}

class ProgressHandler
{
public:
    std::atomic<uint64_t> failed_num;
    std::atomic<uint64_t> success_num;
    uint64_t total_num;
    std::map<std::string, EC> results{};
    ProgressHandler(uint64_t total_num)
    {
        this->failed_num = 0;
        this->success_num = 0;
        this->total_num = total_num;
    }

    void trace(const std::string src, EC result)
    {
        if (result == EC::Success)
        {
            success_num.fetch_add(1);
        }
        else
        {
            failed_num.fetch_add(1);
        }
        results[src] = result;
    };
};

class AESECBDecryptor
{
private:
    EVP_CIPHER_CTX *ctx;

    void unpad(std::vector<uint8_t> &data)
    {
        if (data.empty())
            return;
        uint8_t pad_value = data.back();
        if (pad_value > 0 && pad_value <= AES_BLOCK_SIZE)
        {
            for (size_t i = data.size() - pad_value; i < data.size(); ++i)
            {
                if (data[i] != pad_value && data[i] != 0)
                {
                    return;
                }
            }
            data.resize(data.size() - pad_value);
        }
        else
        {
            return;
        }
    }

public:
    AESECBDecryptor()
    {
        ctx = EVP_CIPHER_CTX_new();
    }

    ~AESECBDecryptor()
    {
        EVP_CIPHER_CTX_free(ctx);
    }

    EC Init(const std::vector<uint8_t> &key)
    {
        if (!ctx)
            return EC::EVPContextCreationFailed;

        const EVP_CIPHER *cipher = nullptr;
        switch (key.size())
        {
        case 16:
            cipher = EVP_aes_128_ecb();
            break;
        case 24:
            cipher = EVP_aes_192_ecb();
            break;
        case 32:
            cipher = EVP_aes_256_ecb();
            break;
        default:
            return EC::InvalidKeySize;
        }
        if (EVP_DecryptInit_ex(ctx, cipher, nullptr, key.data(), nullptr) != 1)
        {
            return EC::KeyInitFailed;
        }
        EVP_CIPHER_CTX_set_padding(ctx, 1);
        return EC::Success;
    }

    bytesr decrypt(const std::vector<uint8_t> &data)
    {
        // 执行解密操作
        std::vector<uint8_t> decrypted(data.size());
        int out_len = 0;

        // 处理数据块（支持大文件分段处理）
        if (EVP_DecryptUpdate(ctx, decrypted.data(), &out_len,
                              data.data(), data.size()) != 1)
        {
            return EC::AESDecryptionFailed;
        }

        // 处理最终块（自动去除填充）
        int final_len = 0;
        if (EVP_DecryptFinal_ex(ctx, decrypted.data() + out_len, &final_len) != 1)
        {
            return EC::AESDecryptionFailed;
        }
        decrypted.resize(out_len + final_len);
        unpad(decrypted);
        return decrypted;
    }
};

class NCMUnlocker
{
private:
    std::vector<byte> core_key;
    std::vector<byte> meta_key;
    std::vector<byte> ncm_header = {'C', 'T', 'E', 'N', 'F', 'D', 'A', 'M'};
    std::atomic<bool> is_terminated;

    bool CheckNcmFormat(const std::vector<byte> &header)
    {
        return header == ncm_header;
    }

    EC CheckPath(const fs::path &src, const fs::path &dst_dir)
    {
        if (!fs::exists(src))
            return EC::SrcNotExist;
        if (!fs::is_regular_file(src))
            return EC::SrcNotFile;
        try
        {
            fs::create_directories(dst_dir);
            return EC::Success;
        }
        catch (const std::exception)
        {
            return EC::DstNotDir;
        }
    }

public:
    size_t default_chunk_size = 8192;

    NCMUnlocker(const std::string core_key = "687A4852416D736F356B496E62617857",
                const std::string meta_key = "2331346C6A6B5F215C5D2630553C2728")
    {
        this->core_key = StringKeyDecode(core_key);
        this->meta_key = StringKeyDecode(meta_key);
    }

    void SetHeader(const std::vector<byte> &header)
    {
        this->ncm_header = header;
    }

    EC BaseUnlock(const std::string src, const std::string dst_dir, size_t chunk_size = 0)
    {
        std::string meta_json;
        try
        {
            fs::path src_path(src);
            fs::path dst_dir_path(dst_dir);
            EC rc = EC::Success;
            bytesr tmp;
            if (chunk_size < 256 || chunk_size > 1024 * 1024 * 16)
            {
                chunk_size = this->default_chunk_size;
            }
            AESECBDecryptor core_decryptor;
            AESECBDecryptor meta_decryptor;
            rc = core_decryptor.Init(this->core_key);
            if (rc != EC::Success)
            {
                return rc;
            }

            rc = meta_decryptor.Init(this->meta_key);
            if (rc != EC::Success)
            {
                return rc;
            }

            rc = CheckPath(src_path, dst_dir_path);
            if (rc != EC::Success)
            {
                return rc;
            }

            // 1. 文件头验证
            std::ifstream fin(src_path, std::ios::binary);
            auto header = read_bytes(fin, 8);
            if (!CheckNcmFormat(header))
            {
                return EC::InvalidSrcFormat;
            }

            // 2. 核心密钥处理
            fin.seekg(2, std::ios::cur); // 跳过2字节
            uint32_t key_len = read_uint32_le(fin);
            auto key_data = read_bytes(fin, key_len);
            for (auto &b : key_data)
                b ^= 0x64; // 异或解码

            tmp = core_decryptor.decrypt(key_data);
            if (std::holds_alternative<EC>(tmp))
            {
                return std::get<EC>(tmp);
            }
            bytes decrypted_key = std::get<bytes>(tmp);

            decrypted_key.erase(decrypted_key.begin(), decrypted_key.begin() + 17);

            // 3. 初始化密钥盒（RC4类似算法）
            std::vector<byte> key_box(256);
            std::iota(key_box.begin(), key_box.end(), 0);
            byte last_byte = 0;
            size_t key_offset = 0;
            for (int i = 0; i < 256; ++i)
            {
                byte swap = key_box[i];
                byte c = (swap + last_byte + decrypted_key[key_offset]) & 0xFF;
                key_offset = (key_offset + 1) % decrypted_key.size();
                std::swap(key_box[i], key_box[c]);
                last_byte = c;
            }

            // 4. 元数据解密
            uint32_t meta_len = read_uint32_le(fin);
            auto meta_data = read_bytes(fin, meta_len);
            for (auto &b : meta_data)
                b ^= 0x63; // 异或解码

            meta_data = base64_decode(std::vector<byte>(
                meta_data.begin() + 22, meta_data.end()));

            tmp = meta_decryptor.decrypt(meta_data);
            if (std::holds_alternative<EC>(tmp))
            {
                return std::get<EC>(tmp);
            }
            bytes decrypted_meta = std::get<bytes>(tmp);

            // 编码为utf8 字符串
            std::string meta_json(reinterpret_cast<const char *>(decrypted_meta.data()), decrypted_meta.size());
            meta_json = meta_json.substr(6);
            json meta = json::parse(meta_json);
            MetaParser meta_parser(meta);
            // 5. 封面解密
            uint32_t crc32 = read_uint32_le(fin);
            fin.seekg(5, std::ios::cur);
            uint32_t img_size = read_uint32_le(fin);
            auto img_data = read_bytes(fin, img_size);

            // 6. 音频数据解密与写入
            fs::create_directories(dst_dir_path);

            std::string music_name = meta_parser.music_name;
            std::string format = meta_parser.format;
            std::string artist_name_str = meta_parser.artist_name;

            fs::path final_path = GetUniquePath(dst_dir_path, music_name, artist_name_str, format);

            std::ofstream fout(final_path, std::ios::binary);
            if (!fout)
            {
                fout.close();
                return EC::OpenDstPathFailed;
            }

            std::vector<byte> chunk(chunk_size);
            uint64_t total_value = 0;
            uint64_t original_value = 0;

            while (fin.read(reinterpret_cast<char *>(chunk.data()), chunk_size))
            {
                size_t bytes_read = fin.gcount();
                for (size_t i = 0; i < bytes_read; ++i)
                {
                    original_value += chunk[i];
                    byte j = (i + 1) & 0xFF;
                    byte a = key_box[j];
                    byte b = key_box[(a + j) & 0xFF];
                    chunk[i] ^= key_box[(a + b) & 0xFF];
                    total_value += chunk[i];
                }
                fout.write(reinterpret_cast<char *>(chunk.data()), bytes_read);
            }
            fout.close();

            // 7. 封面写入
            if (!img_data.empty())
            {
                CoverWrite(final_path, img_data);
            }

            if (format == "unknown")
            {
                // 读取文件头
                std::ifstream fin(final_path, std::ios::binary);
                auto header = read_bytes(fin, 128);
                if (std::string(header.begin(), header.begin() + 4) == "fLaC")
                {
                    format = "flac";
                }
                else if (std::string(header.begin(), header.begin() + 3) == "ID3")
                {
                    format = "mp3";
                }
                else
                {
                    fs::remove(final_path);
                    return EC::InvalidMusicFormat;
                }
                // 使用新format重命名文件
                fs::path new_path = GetUniquePath(dst_dir_path, music_name, artist_name_str, format);
                fs::rename(final_path, new_path);
            }

            return rc;
        }
        catch (const std::exception &e)
        {
            return EC::UnknownError;
        }
    }

    EC CoverWrite(const fs::path &audio_path,
                  const std::vector<byte> &img_data)
    {

        // 检测图片类型 (JPEG/PNG)
        std::string mime_type = "image/jpeg";
        if (img_data.size() > 8 &&
            memcmp(img_data.data(), "\x89PNG\r\n\x1A\n", 8) == 0)
        {
            mime_type = "image/png";
        }
        else if (img_data.size() < 3 ||
                 memcmp(img_data.data(), "\xFF\xD8\xFF", 3) != 0)
        {
            return EC::InvalidCoverFormat;
        }

        try
        {
            // MP3 处理
            if (audio_path.extension() == ".mp3")
            {
                TagLib::MPEG::File file(audio_path.wstring().c_str());
                if (!file.isValid())
                {
                    return EC::OpenSrcFileFailed;
                }

                auto *tag = file.ID3v2Tag(true);
                auto *frame = new TagLib::ID3v2::AttachedPictureFrame;

                frame->setMimeType(mime_type.c_str());
                frame->setPicture(TagLib::ByteVector(
                    reinterpret_cast<const char *>(img_data.data()),
                    img_data.size()));
                frame->setType(TagLib::ID3v2::AttachedPictureFrame::FrontCover);
                tag->addFrame(frame);

                if (!file.save())
                {
                    return EC::SaveFileFailed;
                }
            }
            // FLAC 处理
            else if (audio_path.extension() == ".flac")
            {
                TagLib::FileName fileName(audio_path.wstring().c_str());
                TagLib::FLAC::File file(fileName);

                if (!file.isValid())
                {
                    return EC::OpenSrcFileFailed;
                }

                auto *picture = new TagLib::FLAC::Picture;
                picture->setMimeType(mime_type.c_str());
                picture->setType(TagLib::FLAC::Picture::FrontCover);
                picture->setData(TagLib::ByteVector(
                    reinterpret_cast<const char *>(img_data.data()),
                    img_data.size()));
                picture->setDescription("Album Art");
                file.addPicture(picture);

                if (!file.save())
                {
                    return EC::SaveFileFailed;
                }
            }
            else
            {
                return EC::InvalidMusicFormat;
            }
            return EC::Success;
        }
        catch (const std::exception)
        {
            return EC::TaglibError;
        }
    }

    std::map<std::string, EC> BatchUnlock(std::vector<std::string> srcs, std::string dst_dir, size_t chunk_size = 0, int thread_num = 1, py::object cb = py::none())
    {
        std::vector<std::pair<std::string, std::string>> tasks;
        for (const auto &src : srcs)
        {
            tasks.push_back(std::make_pair(src, dst_dir));
        }
        return MapBatchUnlock(tasks, chunk_size, thread_num, cb);
    }

    std::map<std::string, EC> MapBatchUnlock(std::vector<std::pair<std::string, std::string>> tasks, size_t chunk_size = 0, int thread_num = 1, py::object cb = py::none())
    {
        thread_num = std::min<int>(thread_num, tasks.size());
        thread_num = std::min<int>(thread_num, std::thread::hardware_concurrency());
        thread_num = std::max<int>(thread_num, 1);
        boost::asio::thread_pool pool(thread_num);
        ProgressHandler progress_handler(tasks.size());
        std::shared_ptr<py::function> cb_ptr;
        if (cb.is_none())
        {
            cb_ptr = nullptr;
        }
        else
        {
            cb_ptr = std::make_shared<py::function>(py::cast<py::function>(cb));
        }

        if (thread_num == 1)
        {
            for (const auto &task : tasks)
            {
                EC rc;
                if (is_terminated.load())
                {
                    break;
                }
                else
                {
                    rc = BaseUnlock(task.first, task.second, chunk_size);
                }

                progress_handler.trace(task.first, rc);
                if (cb_ptr)
                {
                    (*cb_ptr)(task.first, rc, progress_handler.success_num.load(), progress_handler.failed_num.load(), progress_handler.total_num);
                }
            }
            return progress_handler.results;
        }

        std::shared_ptr<std::atomic<bool>> is_trace = std::make_shared<std::atomic<bool>>(false);
        std::mutex mtx;
        for (const auto &task : tasks)
        {
            boost::asio::post(pool, [this, task, chunk_size, &progress_handler, cb_ptr, is_trace, &mtx]()
                              {
                EC rc;
                if (is_terminated.load())
                {
                    return;
                }

                rc = BaseUnlock(task.first, task.second, chunk_size);
                
                {
                    std::lock_guard<std::mutex> lock(mtx);
                    progress_handler.trace(task.first, rc);
                    if (cb_ptr)
                    {
                        (*cb_ptr)(task.first, rc, progress_handler.success_num.load(), progress_handler.failed_num.load(), progress_handler.total_num);
                    }
                } });
        }

        pool.join();

        return progress_handler.results;
    }

    void Terminate()
    {
        is_terminated.store(true);
    }
};

PYBIND11_MODULE(NCMUnlocker, m)
{
    py::enum_<EC>(m, "NCMErrorCode")
        .value("Success", EC::Success)
        .value("SrcNotExist", EC::SrcNotExist)
        .value("SrcNotFile", EC::SrcNotFile)
        .value("DstNotDir", EC::DstNotDir)
        .value("InvalidSrcFormat", EC::InvalidSrcFormat)
        .value("InvalidKeySize", EC::InvalidKeySize)
        .value("InvalidDataSize", EC::InvalidDataSize)
        .value("EVPContextCreationFailed", EC::EVPContextCreationFailed)
        .value("KeyInitFailed", EC::KeyInitFailed)
        .value("AESDecryptionFailed", EC::AESDecryptionFailed)
        .value("InvalidCoverFormat", EC::InvalidCoverFormat)
        .value("InvalidMusicFormat", EC::InvalidMusicFormat)
        .value("OpenSrcFileFailed", EC::OpenSrcFileFailed)
        .value("OpenDstPathFailed", EC::OpenDstPathFailed)
        .value("SaveFileFailed", EC::SaveFileFailed)
        .value("TaglibError", EC::TaglibError)
        .value("UnknownError", EC::UnknownError);

    py::class_<NCMUnlocker>(m, "NCMUnlocker")
        .def(py::init<const std::string, const std::string>(),
             py::arg("core_key") = "687A4852416D736F356B496E62617857",
             py::arg("meta_key") = "2331346C6A6B5F215C5D2630553C2728")
        .def("BaseUnlock", &NCMUnlocker::BaseUnlock,
             py::arg("src"),
             py::arg("dst_dir"),
             py::arg("chunk_size") = 0)
        .def("BatchUnlock", &NCMUnlocker::BatchUnlock,
             py::arg("srcs"),
             py::arg("dst_dir"),
             py::arg("chunk_size") = 0,
             py::arg("thread_num") = 1,
             py::arg("cb") = py::none())
        .def("MapBatchUnlock", &NCMUnlocker::MapBatchUnlock,
             py::arg("tasks"),
             py::arg("chunk_size") = 0,
             py::arg("thread_num") = 1,
             py::arg("cb") = py::none())
        .def("SetHeader", &NCMUnlocker::SetHeader,
             py::arg("header"));
}