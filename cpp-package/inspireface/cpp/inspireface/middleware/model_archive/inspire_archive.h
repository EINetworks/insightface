//
// Created by tunm on 2024/3/30.
//

#ifndef MODELLOADERTAR_INSPIREARCHIVE_H
#define MODELLOADERTAR_INSPIREARCHIVE_H
#include "simple_archive.h"
#include "inspire_model/inspire_model.h"
#include "yaml-cpp/yaml.h"
#include "fstream"
#include "mine.h"
#include <numeric>

namespace inspire {

enum {
    MISS_MANIFEST = -11,
    FORMAT_ERROR = -12,
    NOT_MATCH_MODEL = -13,
    ERROR_MODEL_BUFFER = -14,
    NOT_READ = -15,
};

class INSPIRE_API InspireArchive : SimpleArchive {
public:
    InspireArchive() : SimpleArchive() {
        m_status_ = NOT_READ;
    }

    explicit InspireArchive(const std::string &archiveFile) : SimpleArchive(archiveFile) {
        archivePath = archiveFile;
        size_t lastSlashPos = archivePath.find_last_of('/');  // Find the last '/' in the path
        if (lastSlashPos != std::string::npos) {
            archivePath =
              archivePath.substr(0, lastSlashPos);  // Extract substring up to the last '/'
            std::cout << "Parent Folder: " << archivePath << std::endl;
        } else {
            std::cerr << "Invalid path: No parent folder found for " << archivePath << std::endl;
        }

        m_status_ = QueryStatus();
        if (m_status_ == SARC_SUCCESS) {
            m_status_ = loadManifestFile();
        }
    }

    int32_t ReLoad(const std::string &archiveFile) {
        archivePath = archiveFile;
        size_t lastSlashPos = archivePath.find_last_of('/');  // Find the last '/' in the path
        if (lastSlashPos != std::string::npos) {
            archivePath =
              archivePath.substr(0, lastSlashPos);  // Extract substring up to the last '/'
            std::cout << "Parent Folder: " << archivePath << std::endl;
        } else {
            std::cerr << "Invalid path: No parent folder found for " << archivePath << std::endl;
        }

        auto ret = Reset(archiveFile);
        if (ret != SARC_SUCCESS) {
            return ret;
        }
        m_status_ = loadManifestFile();
        return m_status_;
    }

    int32_t QueryStatus() const {
        return m_status_;
    }

    unsigned long calculateChecksum(const std::vector<char> &buffer) {
        return std::accumulate(buffer.begin(), buffer.end(), 0UL);
    }

    int32_t LoadModel(const std::string &name, InspireModel &model) {
        if (m_config_[name]) {
            auto ret = model.Reset(m_config_[name]);
            if (ret != 0) {
                return ret;
            }
            // std::cout << name << std::endl;
            // auto &buffer = GetFileContent(model.name);
            // if (buffer.empty()) {
            //     return ERROR_MODEL_BUFFER;
            // }
            // model.SetBuffer(buffer, buffer.size());
            // printf("FILE Size : %d\n", buffer.size());
            // for (int i = 0; i < 5; i++) {
            //     std::cout << (int)buffer[i] << " ";
            // }
            // int sum=0;
            // for (int i = 0; i < buffer.size(); i++)
            // {
            //     sum+=(int)buffer[i];
            // }
            // printf("Sum : %d\n", sum);

            std::cout << name << std::endl;
            auto &encryptedBuffer = GetFileContent(model.name);
            if (encryptedBuffer.empty()) {
                return ERROR_MODEL_BUFFER;
            }

            if (name == "landmark" || name == "feature") {
                for (size_t i = 0; i < encryptedBuffer.size(); i++) {
                    encryptedBuffer[i] ^= key_ei[i % key_ei.size()];
                }
                printf("FILE Size : %d\n", encryptedBuffer.size());
                for (int i = 0; i < 5; i++) {
                    std::cout << (int)encryptedBuffer[i] << " ";
                }
                int sum = 0;
                for (int i = 0; i < encryptedBuffer.size(); i++) {
                    sum += (int)encryptedBuffer[i];
                }
                printf("Encryted buffer Sum : %d\n", sum);
                std::vector<char> buffer(encryptedBuffer.begin(), encryptedBuffer.end());
                printf("FILE Size : %d\n", buffer.size());
                for (int i = 0; i < 5; i++) {
                    std::cout << (int)buffer[i] << " ";
                }
                sum = 0;
                for (int i = 0; i < buffer.size(); i++) {
                    sum += (int)buffer[i];
                }
                printf("Sum : %d\n", sum);
                
                model.SetBuffer(encryptedBuffer, encryptedBuffer.size());
            } else {
                mine::ByteArray encryptedByteArray(encryptedBuffer.begin(), encryptedBuffer.end());

                // Prepare the key and IV
                mine::ByteArray key(
                  reinterpret_cast<const unsigned char *>(key_ei.data()),
                  reinterpret_cast<const unsigned char *>(key_ei.data()) + key_ei.size());

                mine::ByteArray iv(
                  reinterpret_cast<const unsigned char *>(key_ei.data()),
                  reinterpret_cast<const unsigned char *>(key_ei.data()) + key_ei.size());

                // Decrypt the buffer
                mine::ByteArray decryptedBuffer = aes.decrypt(encryptedByteArray, &key, iv);
                std::vector<char> buffer(decryptedBuffer.begin(), decryptedBuffer.end());

                printf("FILE Size : %d\n", buffer.size());
                for (int i = 0; i < 5; i++) {
                    std::cout << (int)buffer[i] << " ";
                }
                int sum = 0;
                for (int i = 0; i < buffer.size(); i++) {
                    sum += (int)buffer[i];
                }
                printf("Sum : %d\n", sum);
                model.SetBuffer(buffer, buffer.size());
            }
            return SARC_SUCCESS;
        } else {
            return NOT_MATCH_MODEL;
        }
    }

    void PublicPrintSubFiles() {
        PrintSubFiles();
    }

    void Release() {
        m_status_ = NOT_READ;
        Close();
    }

private:
    int32_t loadManifestFile() {
        if (QueryLoadStatus() == SARC_SUCCESS) {
            // auto configBuffer = GetFileContent(MANIFEST_FILE);
            // configBuffer.push_back('\0');
            // if (configBuffer.empty()) {
            //     return MISS_MANIFEST;
            // }
            // m_config_ = YAML::Load(configBuffer.data());
            auto encryptedBuffer = GetFileContent(MANIFEST_FILE);

            // Convert to mine::ByteArray if necessary
            mine::ByteArray encryptedByteArray(encryptedBuffer.begin(), encryptedBuffer.end());

            // Prepare the key and IV
            mine::ByteArray key(
              reinterpret_cast<const unsigned char *>(key_ei.data()),
              reinterpret_cast<const unsigned char *>(key_ei.data()) + key_ei.size());

            mine::ByteArray iv(
              reinterpret_cast<const unsigned char *>(key_ei.data()),
              reinterpret_cast<const unsigned char *>(key_ei.data()) + key_ei.size());

            // Decrypt the buffer
            mine::ByteArray decryptedBuffer = aes.decrypt(encryptedByteArray, &key, iv);

            // unsigned long checksum = calculateChecksum(decryptedBuffer);
            // std::cout << "Simple checksum of the mannifest pre buffer: " << checksum << '\n';
            // Null-terminate the decrypted data
            decryptedBuffer.push_back('\0');
            if (decryptedBuffer.empty()) {
                return MISS_MANIFEST;
            }

           
            m_config_ = YAML::Load(reinterpret_cast<const char *>(decryptedBuffer.data()));
            if (!m_config_["tag"] || !m_config_["version"]) {
                return FORMAT_ERROR;
            }
            m_tag_ = m_config_["tag"].as<std::string>();
            m_version_ = m_config_["version"].as<std::string>();
            INSPIRE_LOGI("== %s %s ==", m_tag_.c_str(), m_version_.c_str());
        }
        return 0;
    }

private:
    YAML::Node m_config_;

    int32_t m_status_;

    const std::string MANIFEST_FILE = "__inspire__";

    std::string m_tag_;
    std::string m_version_;
    std::string key_ei = "time123456789123";
    mine::AES aes;
    std::string archivePath;
};

}  // namespace inspire

#endif  // MODELLOADERTAR_INSPIREARCHIVE_H
