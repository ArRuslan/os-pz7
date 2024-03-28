#include <cstdint>
#include <cstring>
#include <iostream>
#include <fstream>
#include <string>
#include <zlib.h> // For CRC32
#include <dlfcn.h> // For dlopen, dlclose, dlsym

bool read_checksum(std::ifstream &file, uint32_t* checksum_out) {
    file.seekg(-12, std::ios::end);
    char* keywordbuf = new char[8];
    file.read(keywordbuf, 8);
    if(std::string(keywordbuf) != "checksum") {
        delete[] keywordbuf;
        return false;
    }
    char* checksumBuf = new char[4];
    file.read(checksumBuf, 4);
    memcpy(checksum_out, checksumBuf, 4);
    delete[] checksumBuf;

    return true;
}

uint32_t get_checksum(char *buf, uint32_t size) {
    uint32_t checksum = 0;
    auto *u32arr = (uint32_t*) buf;
    for (uint32_t i = 0; i < size / 4; ++i)
        checksum += u32arr[i];

    uint32_t left = size % 4;
    if (left) {
        buf += size;
        uint32_t left_cs = 0;
        memcpy(&left_cs, buf, left);
        checksum += left_cs;
    }

    return checksum;
}

void write_checksum(const std::string &path) {
    std::ifstream file(path, std::ios::binary);
    uint32_t checksum;
    bool checksum_present = read_checksum(file, &checksum);

    file.seekg(0, std::ios::end);
    size_t file_size = file.tellg();
    if(checksum_present)
        file_size -= 12;
    char* buf = new char[file_size];
    file.seekg(0);
    file.read(buf, file_size);
    checksum = get_checksum(buf, file_size);
    delete[] buf;

    file.close();
    std::ofstream out_file(path, std::ios::ate | std::ios::in | std::ios::out | std::ios::binary);

    if(!checksum_present) {
        char checksumKw[] = "checksum\0\0\0\0";
        out_file.write(checksumKw, 12);
    }

    out_file.seekp(-4, std::ios::end);
    char* checksumBuf = new char[4];
    memcpy(checksumBuf, &checksum, 4);
    out_file.write(checksumBuf, 4);

    delete[] checksumBuf;
    out_file.close();
}

void *dlopen_checksum(const std::string& path, bool fail_on_mismatch = false) {
    std::ifstream file(path, std::ios::binary);
    uint32_t checksum;
    if(!read_checksum(file, &checksum)) {
        printf("Checksum not found!\n");
        file.close();
        if(fail_on_mismatch)
            return nullptr;
        printf("Writing new!\n");
        write_checksum(path);
        return dlopen(path.c_str(), RTLD_LAZY);
    }

    file.seekg(0, std::ios::end);
    int file_size = (int)file.tellg() - 12;
    char* buf = new char[file_size];
    file.seekg(0);
    file.read(buf, file_size);
    if(get_checksum(buf, file_size) != checksum) {
        printf("Checksum mismatch!\n");
        file.close();
        delete[] buf;
        if(fail_on_mismatch)
            return nullptr;
        printf("Writing new!\n");
        write_checksum(path);
        return dlopen(path.c_str(), RTLD_LAZY);
    }

    delete[] buf;

    return dlopen(path.c_str(), RTLD_LAZY);
}

typedef int64_t (*add_t)(int64_t, int64_t);

int main() {
    //write_checksum("../liblib_dyn.so");

    void* handle = dlopen_checksum("../liblib_dyn.so", true);
    if (!handle) {
        printf("Failed to load DLL!\n");
        return 1;
    }

    auto add = reinterpret_cast<add_t>(dlsym(handle, "add_c"));
    printf("1 + 2 = %ld\n", add(1, 2));
    dlclose(handle);

    return 0;
}
