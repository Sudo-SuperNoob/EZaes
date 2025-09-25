#include <iostream>
#include <windows.h>
#include <vector>
#include <string>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <stdexcept>




typedef LONG(WINAPI* RtlGetVersionPtr)(OSVERSIONINFOEXW*);

using namespace std;

struct AesKey {
    vector<unsigned char> key;
    vector<unsigned char> iv;
};

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

std::string readFileToString(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary); // binary � ����� �� ������� �������� ������
    if (!file.is_open()) {
        return "ba837e2224e78a34ac3d692634d2705d45ce9450c88b6e4e1795caa74627fe6a7965177d297c46585730b7660da2a1a6000";
    }

    std::ostringstream buffer;
    buffer << file.rdbuf();  // ������ ���� �����
    return buffer.str();
}

void writeStringToFile(const std::string& filename, const std::string& data) {
    std::ofstream file(filename, std::ios::binary); // binary � ����� �� ������� ������
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open file: " + filename);
    }

    file.write(data.data(), static_cast<std::streamsize>(data.size()));
    if (!file) {
        throw std::runtime_error("Failed to write data to file: " + filename);
    }
}


AesKey generateAesKey() {
    AesKey aesKey;
    aesKey.key.resize(32); // AES-256
    aesKey.iv.resize(16);  // IV 16 bytes

    if (RAND_bytes(aesKey.key.data(), static_cast<int>(aesKey.key.size())) != 1) handleErrors();
    if (RAND_bytes(aesKey.iv.data(), static_cast<int>(aesKey.iv.size())) != 1) handleErrors();

    return aesKey;
}

std::string toHex(const std::vector<unsigned char>& data) {
    std::ostringstream oss;
    for (unsigned char c : data) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)c;
    }
    return oss.str();
}


// ������ ������ � ���������
void printWrappedLine(const std::string& label, const std::string& value, size_t labelWidth, size_t colWidth) {
    size_t offset = 0;

    // ������ ������ � �������
    std::cout << "\t|\033[1m\033[42m" << std::left << std::setw(labelWidth) << label << "\033[0m| ";

    while (offset < value.size()) {
        std::cout << value.substr(offset, colWidth);

        offset += colWidth;
        if (offset < value.size()) {
            std::cout << "\n\t|" << std::setw(labelWidth) << " " << "| ";
        }
    }
    std::cout << "\n";
}

vector<unsigned char> encrypt(const string& plaintext, const AesKey& aesKey) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aesKey.key.data(), aesKey.iv.data()) != 1) handleErrors();

    int block_size = EVP_CIPHER_block_size(EVP_aes_256_cbc());
    vector<unsigned char> ciphertext(plaintext.size() + block_size);

    int len = 0;
    int ciphertext_len = 0;

    if (EVP_EncryptUpdate(ctx,
        ciphertext.data(), &len,
        reinterpret_cast<const unsigned char*>(plaintext.data()),
        static_cast<int>(plaintext.size())) != 1) handleErrors();
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + ciphertext_len, &len) != 1) handleErrors();
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    ciphertext.resize(ciphertext_len);
    return ciphertext;
}

string decrypt(const vector<unsigned char>& ciphertext, const AesKey& aesKey) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aesKey.key.data(), aesKey.iv.data()) != 1) handleErrors();

    vector<unsigned char> plaintext(ciphertext.size());
    int len = 0;
    int plaintext_len = 0;

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), static_cast<int>(ciphertext.size())) != 1) handleErrors();
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + plaintext_len, &len) != 1) handleErrors();
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    plaintext.resize(plaintext_len);
    return string(plaintext.begin(), plaintext.end());
}

std::vector<unsigned char> fromHex(const std::string& hexString) {
    if (hexString.length() % 2 != 0) {
        // �������� ��������� ������, ���� ����� ��������
        // ��������, ��������� ���������� ��� ������� ������ ������
        std::cerr << "������: ����� HEX-������ ��������.\n";
        return {};
    }

    std::vector<unsigned char> bytes;
    bytes.reserve(hexString.length() / 2);
    for (size_t i = 0; i < hexString.length(); i += 2) {
        std::string byteString = hexString.substr(i, 2);
        unsigned int byte = 0;
        std::stringstream ss;
        ss << std::hex << byteString;
        ss >> byte;
        bytes.push_back(static_cast<unsigned char>(byte));
    }
    return bytes;
}



bool isWindows10OrGreater() {
    HMODULE hMod = ::GetModuleHandleW(L"ntdll.dll");
    if (hMod) {
        auto f = (RtlGetVersionPtr)::GetProcAddress(hMod, "RtlGetVersion");
        if (f != nullptr) {
            OSVERSIONINFOEXW osvi = {};
            osvi.dwOSVersionInfoSize = sizeof(osvi);
            if (f(&osvi) == 0) {
                return (osvi.dwMajorVersion > 10) ||
                    (osvi.dwMajorVersion == 10 && osvi.dwMinorVersion >= 0);
            }
        }
    }
    return false;
}

int main() {
    SetConsoleCP(CP_UTF8);
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleTitle(L"EZaes by SuperNoob v1");
    if (isWindows10OrGreater()) {
        while (true) {
            system("cls");
            char UserInput0;
            cout << "\n\n\t\t\033[4m\033[1mEZaes by SuperNoob v1.0\033[0m\n\n\t1. �����������\n\t2. ������������\n\t0. �����\n\t>>>";
            cin >> UserInput0;
            if (UserInput0 == '1') {
                system("cls");
                cout << "\n\n\n\t1. �����\n\t2. ����\n\t>>> ";
                cin >> UserInput0;
                if (UserInput0 == '1') {
                    system("cls");
                    std::cout << "\n\n\n\t����� �����\n\t>>> ";

                    std::string message;
                    cin.ignore();
                    getline(cin, message);

                    AesKey key = generateAesKey();
                    auto cipher = encrypt(message, key);

                    std::string cipherHex = toHex(cipher);
                    std::string keyHex = toHex(key.key);
                    std::string ivHex = toHex(key.iv);

                    size_t labelWidth = 11; // ������ ������� � �������
                    size_t colWidth = 80; // ������ ������� � �������

                    // ���� �����
                    std::cout << "\t+" << std::string(labelWidth, '-') << "+" << std::string(colWidth + 1, '-') << "+\n";

                    // �������� ��� ������ � ���������
                    printWrappedLine("Encrypted", cipherHex, labelWidth, colWidth);
                    std::cout << "\t+" << std::string(labelWidth, '-') << "+" << std::string(colWidth + 1, '-') << "+\n";
                    printWrappedLine("Key", keyHex, labelWidth, colWidth);
                    std::cout << "\t+" << std::string(labelWidth, '-') << "+" << std::string(colWidth + 1, '-') << "+\n";
                    printWrappedLine("IV", ivHex, labelWidth, colWidth);

                    // ������ �����
                    std::cout << "\t+" << std::string(labelWidth, '-') << "+" << std::string(colWidth + 1, '-') << "+\n";
                    system("pause");
                }
                else if (UserInput0 == '2') {
                    system("cls");
                    std::cout << "\n\n\n\t����� �������� �����(�� ������ ���� � ����� � �����������)\n\t>>> ";

                    std::string message;
                    std::cin >> message;

                    AesKey key = generateAesKey();
                    if (readFileToString(message) == "ba837e2224e78a34ac3d692634d2705d45ce9450c88b6e4e1795caa74627fe6a7965177d297c46585730b7660da2a1a6000") {
                        cerr << "\t���� �� ������!\n";
                        system("pause");
                        return 1;
                    }
                    auto cipher = encrypt(readFileToString(message), key);

                    std::string cipherHex = toHex(cipher);
                    std::string keyHex = toHex(key.key);
                    std::string ivHex = toHex(key.iv);

                    size_t labelWidth = 11; // ������ ������� � �������
                    size_t colWidth = 80; // ������ ������� � �������
                    writeStringToFile("base.bin", cipherHex);
                    // ���� �����
                    std::cout << "\t+" << std::string(labelWidth, '-') << "+" << std::string(colWidth + 1, '-') << "+\n";

                    // �������� ��� ������ � ���������
                    printWrappedLine("Encrypted", "Save in file base.bin", labelWidth, colWidth);
                    std::cout << "\t+" << std::string(labelWidth, '-') << "+" << std::string(colWidth + 1, '-') << "+\n";
                    printWrappedLine("Key", keyHex, labelWidth, colWidth);
                    std::cout << "\t+" << std::string(labelWidth, '-') << "+" << std::string(colWidth + 1, '-') << "+\n";
                    printWrappedLine("IV", ivHex, labelWidth, colWidth);

                    // ������ �����
                    std::cout << "\t+" << std::string(labelWidth, '-') << "+" << std::string(colWidth + 1, '-') << "+\n";
                    system("pause");
                }
            }

            else if (UserInput0 == '2') { // ������������, ��� '2' �������� "�����������"
                system("cls");
                // �����������: �������� ������ ��� ������������
                std::cout << "\n\n\n\t1. ������������ �����\n\t2. ������������ ����\n\t>>> ";
                cin >> UserInput0;
                if (UserInput0 == '1') { // ���� ������������ ������ "������������ �����"
                    system("cls");

                    cout << "\n\n\n\t����� ������������ ����� (HEX)\n\t>>> ";
                    string messageHex; // ������������� ��� �������
                    cin >> messageHex;

                    // �����������: ����������� HEX-������ � �������� ������
                    std::vector<unsigned char> cipherBytes = fromHex(messageHex);
                    if (cipherBytes.empty() && !messageHex.empty()) { // �������� �� ������ fromHex
                        cerr << "������: �������� ������ �������������� ����� (HEX).\n";
                        return 1;
                    }


                    cout << "\n\n\n\t����� Key (HEX)\n\t>>> ";
                    string KeyHex; // ������������� ��� �������
                    cin >> KeyHex;

                    cout << "\n\n\n\t����� IV (HEX)\n\t>>> ";
                    string IVHex; // ������������� ��� �������
                    cin >> IVHex;

                    AesKey key;
                    // �����������: ���������� ��������� �� ������� � ������������� fromHex
                    if (KeyHex.size() != 64) {
                        cerr << "������: Key ������ ���� ����� 64 �������� (32 ����� AES-256)!\n";
                        return 1;
                    }
                    if (IVHex.size() != 32) {
                        cerr << "������: IV ������ ���� ����� 32 �������� (16 ���� AES)!\n";
                        return 1;
                    }

                    key.key = fromHex(KeyHex);
                    key.iv = fromHex(IVHex);

                    // ����� �������� ���� ������� decrypt
                    // �����������: �������� ���������� �������� ������
                    string decryptedPlaintext = decrypt(cipherBytes, key); // <-- ��������� ��������� decrypt

                    size_t labelWidth = 11;
                    size_t colWidth = 80;

                    cout << "\t+" << string(labelWidth, '-') << "+" << string(colWidth + 1, '-') << "+\n";
                    // �����������: ������� ������������� ����� ��� ���������� ����������
                    printWrappedLine("Decrypted", decryptedPlaintext, labelWidth, colWidth);
                    cout << "\t+" << string(labelWidth, '-') << "+" << string(colWidth + 1, '-') << "+\n";
                    // ������� ��������� Key � IV ��� �������
                    printWrappedLine("Key (HEX)", KeyHex, labelWidth, colWidth);
                    cout << "\t+" << string(labelWidth, '-') << "+" << string(colWidth + 1, '-') << "+\n";
                    printWrappedLine("IV (HEX)", IVHex, labelWidth, colWidth);
                    // �����������: ��������� ������ �����
                    cout << "\t+" << string(labelWidth, '-') << "+" << string(colWidth + 1, '-') << "+\n";
                    system("pause");
                }
                else if (UserInput0 == '2') {
                    if (UserInput0 == '2') { // ���� ������������ ������ "������������ �����"
                        system("cls");

                        cout << "\n\n\n\t����� �������� ������������� �����\n\t>>> ";
                        string message; // ������������� ��� �������
                        cin >> message;
                        if (readFileToString(message) == "ba837e2224e78a34ac3d692634d2705d45ce9450c88b6e4e1795caa74627fe6a7965177d297c46585730b7660da2a1a6000") {
                            cerr << "\t���� �� ������!\n";
                            system("pause");
                            return 1;
                        }
                        string messageHex = readFileToString(message);
                        // �����������: ����������� HEX-������ � �������� ������
                        std::vector<unsigned char> cipherBytes = fromHex(messageHex);
                        if (cipherBytes.empty() && !messageHex.empty()) { // �������� �� ������ fromHex
                            cerr << "������: �������� ������ �������������� ����� (HEX).\n";
                            return 1;
                        }
                        cout << "\n\n\n\t����� �������� ������������� �����\n\t>>> ";
                        string ExFileName; // ������������� ��� �������
                        cin >> ExFileName;

                        cout << "\n\n\n\t����� Key (HEX)\n\t>>> ";
                        string KeyHex; // ������������� ��� �������
                        cin >> KeyHex;

                        cout << "\n\n\n\t����� IV (HEX)\n\t>>> ";
                        string IVHex; // ������������� ��� �������
                        cin >> IVHex;

                        AesKey key;
                        // �����������: ���������� ��������� �� ������� � ������������� fromHex
                        if (KeyHex.size() != 64) {
                            cerr << "������: Key ������ ���� ����� 64 �������� (32 ����� AES-256)!\n";
                            return 1;
                        }
                        if (IVHex.size() != 32) {
                            cerr << "������: IV ������ ���� ����� 32 �������� (16 ���� AES)!\n";
                            return 1;
                        }

                        key.key = fromHex(KeyHex);
                        key.iv = fromHex(IVHex);

                        // ����� �������� ���� ������� decrypt
                        // �����������: �������� ���������� �������� ������
                        string decryptedPlaintext = decrypt(cipherBytes, key); // <-- ��������� ��������� decrypt

                        size_t labelWidth = 11;
                        size_t colWidth = 80;
                        string last = "������������ � ����" + ExFileName;
                        cout << "\t+" << string(labelWidth, '-') << "+" << string(colWidth + 1, '-') << "+\n";
                        // �����������: ������� ������������� ����� ��� ���������� ����������
                        printWrappedLine("Decrypted", last, labelWidth, colWidth);
                        cout << "\t+" << string(labelWidth, '-') << "+" << string(colWidth + 1, '-') << "+\n";
                        // ������� ��������� Key � IV ��� �������
                        printWrappedLine("Key (HEX)", KeyHex, labelWidth, colWidth);
                        cout << "\t+" << string(labelWidth, '-') << "+" << string(colWidth + 1, '-') << "+\n";
                        printWrappedLine("IV (HEX)", IVHex, labelWidth, colWidth);
                        // �����������: ��������� ������ �����
                        cout << "\t+" << string(labelWidth, '-') << "+" << string(colWidth + 1, '-') << "+\n";
                        system("pause");
                    }
                }

            }
        }










        //string decrypted = decrypt(cipher, key);
        //cout << "Decrypted: " << decrypted << endl;
    }


    else {
        cout << "Sorry, but this program works on Windows 10 and above.";
        system("pause");
        return 1;
    }

    return 0;
}