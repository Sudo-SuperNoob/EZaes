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

string readFileToString(const string& filename) {
    ifstream file(filename, ios::binary); 
    if (!file.is_open()) {
        return "ba837e2224e78a34ac3d692634d2705d45ce9450c88b6e4e1795caa74627fe6a7965177d297c46585730b7660da2a1a6000";
    }

    ostringstream buffer;
    buffer << file.rdbuf();  
    return buffer.str();
}

void writeStringToFile(const string& filename, const string& data) {
    ofstream file(filename, ios::binary); 
    if (!file.is_open()) {
        throw runtime_error("Cannot open file: " + filename);
    }

    file.write(data.data(), static_cast<streamsize>(data.size()));
    if (!file) {
        throw runtime_error("Failed to write data to file: " + filename);
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

string toHex(const vector<unsigned char>& data) {
    ostringstream oss;
    for (unsigned char c : data) {
        oss << hex << setw(2) << setfill('0') << (int)c;
    }
    return oss.str();
}



void printWrappedLine(const string& label, const string& value, size_t labelWidth, size_t colWidth) {
    size_t offset = 0;


    cout << "\t|\033[1m\033[42m" << left << setw(labelWidth) << label << "\033[0m| ";

    while (offset < value.size()) {
        cout << value.substr(offset, colWidth);

        offset += colWidth;
        if (offset < value.size()) {
            cout << "\n\t|" << setw(labelWidth) << " " << "| ";
        }
    }
    cout << "\n";
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

vector<unsigned char> fromHex(const string& hexString) {
    if (hexString.length() % 2 != 0) {
        cerr << "Ошибка: Длина HEX-строки нечетная.\n";
        return {};
    }

    vector<unsigned char> bytes;
    bytes.reserve(hexString.length() / 2);
    for (size_t i = 0; i < hexString.length(); i += 2) {
        string byteString = hexString.substr(i, 2);
        unsigned int byte = 0;
        stringstream ss;
        ss << hex << byteString;
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
            cout << "\n\n\t\t\033[4m\033[1mEZaes by SuperNoob v1.0\033[0m\n\n\t1. Зашифровать\n\t2. Разшифровать\n\t0. Выход\n\t>>>";
            cin >> UserInput0;
            if (UserInput0 == '1') {
                system("cls");
                cout << "\n\n\n\t1. Слово\n\t2. Файл\n\t>>> ";
                cin >> UserInput0;
                if (UserInput0 == '1') {
                    system("cls");
                    cout << "\n\n\n\tВведи слово\n\t>>> ";

                    string message;
                    cin.ignore();
                    getline(cin, message);

                    AesKey key = generateAesKey();
                    auto cipher = encrypt(message, key);

                    string cipherHex = toHex(cipher);
                    string keyHex = toHex(key.key);
                    string ivHex = toHex(key.iv);

                    size_t labelWidth = 11; 
                    size_t colWidth = 80; 

                    
                    cout << "\t+" << string(labelWidth, '-') << "+" << string(colWidth + 1, '-') << "+\n";

                    
                    printWrappedLine("Encrypted", cipherHex, labelWidth, colWidth);
                    cout << "\t+" << string(labelWidth, '-') << "+" << string(colWidth + 1, '-') << "+\n";
                    printWrappedLine("Key", keyHex, labelWidth, colWidth);
                    cout << "\t+" << string(labelWidth, '-') << "+" << string(colWidth + 1, '-') << "+\n";
                    printWrappedLine("IV", ivHex, labelWidth, colWidth);

                    
                    cout << "\t+" << string(labelWidth, '-') << "+" << string(colWidth + 1, '-') << "+\n";
                    system("pause");
                }
                else if (UserInput0 == '2') {
                    system("cls");
                    cout << "\n\n\n\tВведи название файла(он должен быть в папке с приложением)\n\t>>> ";

                    string message;
                    cin >> message;

                    AesKey key = generateAesKey();
                    if (readFileToString(message) == "ba837e2224e78a34ac3d692634d2705d45ce9450c88b6e4e1795caa74627fe6a7965177d297c46585730b7660da2a1a6000") {
                        cerr << "\tФайл не найден!\n";
                        system("pause");
                        return 1;
                    }
                    auto cipher = encrypt(readFileToString(message), key);

                    string cipherHex = toHex(cipher);
                    string keyHex = toHex(key.key);
                    string ivHex = toHex(key.iv);

                    size_t labelWidth = 11; 
                    size_t colWidth = 80; 
                    writeStringToFile("base.bin", cipherHex);

                    cout << "\t+" << string(labelWidth, '-') << "+" << string(colWidth + 1, '-') << "+\n";

                    printWrappedLine("Encrypted", "Save in file base.bin", labelWidth, colWidth);
                    cout << "\t+" << string(labelWidth, '-') << "+" << string(colWidth + 1, '-') << "+\n";
                    printWrappedLine("Key", keyHex, labelWidth, colWidth);
                    cout << "\t+" << string(labelWidth, '-') << "+" << string(colWidth + 1, '-') << "+\n";
                    printWrappedLine("IV", ivHex, labelWidth, colWidth);

                    cout << "\t+" << string(labelWidth, '-') << "+" << string(colWidth + 1, '-') << "+\n";
                    system("pause");
                }
            }

            else if (UserInput0 == '2') { 
                system("cls");
                cout << "\n\n\n\t1. Расшифровать слово\n\t2. Расшифровать файл\n\t>>> ";
                cin >> UserInput0;
                if (UserInput0 == '1') {
                    system("cls");

                    cout << "\n\n\n\tВведи зашифрованое слово (HEX)\n\t>>> ";
                    string messageHex; 
                    cin >> messageHex;


                    vector<unsigned char> cipherBytes = fromHex(messageHex);
                    if (cipherBytes.empty() && !messageHex.empty()) { 
                        cerr << "Ошибка: Неверный формат зашифрованного слова (HEX).\n";
                        return 1;
                    }


                    cout << "\n\n\n\tВведи Key (HEX)\n\t>>> ";
                    string KeyHex;
                    cin >> KeyHex;

                    cout << "\n\n\n\tВведи IV (HEX)\n\t>>> ";
                    string IVHex; 
                    cin >> IVHex;

                    AesKey key;

                    if (KeyHex.size() != 64) {
                        cerr << "Ошибка: Key должен быть равен 64 символам (32 байта AES-256)!\n";
                        return 1;
                    }
                    if (IVHex.size() != 32) {
                        cerr << "Ошибка: IV должен быть равен 32 символам (16 байт AES)!\n";
                        return 1;
                    }

                    key.key = fromHex(KeyHex);
                    key.iv = fromHex(IVHex);

                    string decryptedPlaintext = decrypt(cipherBytes, key); 

                    size_t labelWidth = 11;
                    size_t colWidth = 80;

                    cout << "\t+" << string(labelWidth, '-') << "+" << string(colWidth + 1, '-') << "+\n";

                    printWrappedLine("Decrypted", decryptedPlaintext, labelWidth, colWidth);
                    cout << "\t+" << string(labelWidth, '-') << "+" << string(colWidth + 1, '-') << "+\n";

                    printWrappedLine("Key (HEX)", KeyHex, labelWidth, colWidth);
                    cout << "\t+" << string(labelWidth, '-') << "+" << string(colWidth + 1, '-') << "+\n";
                    printWrappedLine("IV (HEX)", IVHex, labelWidth, colWidth);

                    cout << "\t+" << string(labelWidth, '-') << "+" << string(colWidth + 1, '-') << "+\n";
                    system("pause");
                }
                else if (UserInput0 == '2') {
                    if (UserInput0 == '2') { 
                        system("cls");

                        cout << "\n\n\n\tВведи название зашифрованого файла\n\t>>> ";
                        string message; 
                        cin >> message;
                        if (readFileToString(message) == "ba837e2224e78a34ac3d692634d2705d45ce9450c88b6e4e1795caa74627fe6a7965177d297c46585730b7660da2a1a6000") {
                            cerr << "\tФайл не найден!\n";
                            system("pause");
                            return 1;
                        }
                        string messageHex = readFileToString(message);

                        vector<unsigned char> cipherBytes = fromHex(messageHex);
                        if (cipherBytes.empty() && !messageHex.empty()) { // Проверка на ошибку fromHex
                            cerr << "Ошибка: Неверный формат зашифрованного слова (HEX).\n";
                            return 1;
                        }
                        cout << "\n\n\n\tВведи название зашифрованого файла\n\t>>> ";
                        string ExFileName; 
                        cin >> ExFileName;

                        cout << "\n\n\n\tВведи Key (HEX)\n\t>>> ";
                        string KeyHex; 
                        cin >> KeyHex;

                        cout << "\n\n\n\tВведи IV (HEX)\n\t>>> ";
                        string IVHex;
                        cin >> IVHex;

                        AesKey key;
                        if (KeyHex.size() != 64) {
                            cerr << "Ошибка: Key должен быть равен 64 символам (32 байта AES-256)!\n";
                            return 1;
                        }
                        if (IVHex.size() != 32) {
                            cerr << "Ошибка: IV должен быть равен 32 символам (16 байт AES)!\n";
                            return 1;
                        }

                        key.key = fromHex(KeyHex);
                        key.iv = fromHex(IVHex);

                        string decryptedPlaintext = decrypt(cipherBytes, key); 

                        size_t labelWidth = 11;
                        size_t colWidth = 80;
                        string last = "Разшифровано в файл" + ExFileName;
                        cout << "\t+" << string(labelWidth, '-') << "+" << string(colWidth + 1, '-') << "+\n";

                        printWrappedLine("Decrypted", last, labelWidth, colWidth);
                        cout << "\t+" << string(labelWidth, '-') << "+" << string(colWidth + 1, '-') << "+\n";

                        printWrappedLine("Key (HEX)", KeyHex, labelWidth, colWidth);
                        cout << "\t+" << string(labelWidth, '-') << "+" << string(colWidth + 1, '-') << "+\n";
                        printWrappedLine("IV (HEX)", IVHex, labelWidth, colWidth);

                        cout << "\t+" << string(labelWidth, '-') << "+" << string(colWidth + 1, '-') << "+\n";
                        system("pause");
                    }
                }

            }
        }

    }


    else {
        cout << "Sorry, but this program works on Windows 10 and above.";
        system("pause");
        return 1;
    }

    return 0;
}