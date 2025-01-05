#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <random>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <secp256k1.h>
#include <thread>
#include <mutex>
#include <chrono>
#include <atomic>
#include <fstream>
#include <unistd.h>
#include <stdexcept>

/*
403b3d4fcff56a92f335a0cf570e4xbxb17b2a6x867x86a84x0x8x3x3x3x7x3x"
_0_b_d_f_f_5_a_2_3_5_0_f_7_e_x_x_1_b_a_x_6_x_6_8_x_x_x_x_x_x_x_x
 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 2 1 2 3 4
1-0
2-b
3-d
4-f
5-f
6-5
7-a
8-2
9-3
10-5
11-
12-
13-
14
15-
16-
17
18
19-
20-
21-
22-
23-
24-8

 =  [0x8000000000000x800000000000,0x9FFFFFFFFFFF,
    0xA000000000000xA00000000000,0xBFFFFFFFFFFF,
    0xC000000000000xC00000000000,0xDFFFFFFFFFFF,
    0xE000000000000xE00000000000,0xFFFFFFFFFFFF]


*/


class Secp {
private:
    std::mutex monitor_mutex;
    std::atomic<long long> total_senhas_verificadas{0};
    std::atomic<bool> chaveEncontrada{false};

    int time_to_show = 30;
    int bits=0;
    std::string password_to_show;

    std::string first_position;
    std::vector<int> indices;

    long long start_first_position, end_first_position;
    std::chrono::steady_clock::time_point inicio;

    static uint32_t xorshift32(uint32_t& state) {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        return state;
    }

public:
    Secp() : inicio(std::chrono::steady_clock::now()) {}

    void help() const {
        std::cout << "Usage: program [options]\n"
                  << "Options:\n"
                  << "  -h                Show help message\n"
                  << "  -a <address>      Set the address rmd160\n"
                  << "  -b <bit num>      Set the bit number for other puzzle numbers"
                  << "  -k <key>          Set the key with 'x' for random generation\n"
                  << "  -s <time_to_show> Set time to show status, when -s 0 show only base key\n"
                  << "  -t <thread num>   Set thread number\n"
                  << "Example:\n"
                  << "./main -a 032ddf76d2ad152cb5b391bfba3d24251a6548dc -k 403b3d4fcff56a92f335a0cf570e4xbxb17b2a6x867x86a84x0x8x3x3X3x7x3x -t 4 -s 30\n"
                  <<"./main -a 739437bb3dd6d1983e66629c5f08c70e52769371 -b 67 -t 4 -s 10\n";
    }

    void save(const std::string& chave) {
        std::ofstream file("keyfound.txt");
        if (!file.is_open()) {
            std::cerr << "[!] Error opening file for writing!" << std::endl;
            return;
        }
        file << "Private key found: " << chave << std::endl;
        file.close();
    }

    std::vector<unsigned char> sha256(const std::vector<unsigned char>& data) const {
        std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
        SHA256(data.data(), data.size(), hash.data());
        return hash;
    }

    std::vector<unsigned char> ripemd160(const std::vector<unsigned char>& data) const {
        std::vector<unsigned char> hash(RIPEMD160_DIGEST_LENGTH);
        RIPEMD160(data.data(), data.size(), hash.data());
        return hash;
    }

    std::vector<uint8_t> hexToBytes(const std::string &hex)
    {
        std::vector<uint8_t> bytes(hex.length() / 2);
        for (size_t i = 0; i < bytes.size(); i++)
        {
            sscanf(&hex[i * 2], "%2hhx", &bytes[i]);
        }
        return bytes;
    }

    std::vector<unsigned char> generateBitcoinAddress(const std::vector<unsigned char>& privateKeyBytes, secp256k1_context* ctx) const {
        if (privateKeyBytes.size() != 32) {
            throw std::invalid_argument("Private key must be exactly 32 bytes.");
        }

        secp256k1_pubkey pubkey;
        if (!secp256k1_ec_pubkey_create(ctx, &pubkey, privateKeyBytes.data())) {
            throw std::runtime_error("Error creating public key. Check the private key.");
        }

        unsigned char pubkeySerialized[33];
        size_t pubkeySerializedLen = sizeof(pubkeySerialized);
        secp256k1_ec_pubkey_serialize(ctx, pubkeySerialized, &pubkeySerializedLen, &pubkey, SECP256K1_EC_COMPRESSED);

        auto shaHash = sha256({pubkeySerialized, pubkeySerialized + pubkeySerializedLen});
        return ripemd160(shaHash);
    }

    std::string generateRandomKey(const std::string& templateKey) {
    uint32_t state = static_cast<uint32_t>(std::chrono::steady_clock::now().time_since_epoch().count());
    std::string result = templateKey;

    std::random_device rd;  // Gerador de números aleatórios baseado em hardware
    std::mt19937 gen(rd());  // Motor de números aleatórios
    std::uniform_int_distribution<> dis(0, 15);
    std::uniform_int_distribution<> disHigh(8, 15); // Para valores de '8' a 'f'

    for (size_t i = 0; i < indices.size(); i++) {
        if (i == 7) {  // Caso especial para índice 29
            int valor = disHigh(gen); // Sorteia apenas valores entre 8 e 15
            if (valor < 10) {
                result[indices[i]] = ('0' + valor);  // Para valores entre 8 e 9
            } else {
                result[indices[i]] = ('a' + (valor - 10));  // Para valores entre 'a' e 'f'
            }
        } else {
            int valor = dis(gen);
            if (valor < 10) {
                result[indices[i]] = ('0' + valor);  // Para valores entre 0 e 9
            } else {
                result[indices[i]] = ('a' + (valor - 10));  // Para valores entre 'a' e 'f'
            }
        }
    }

    return result;
}






    void monitorStatus() {

        while (!chaveEncontrada.load()) {
            std::this_thread::sleep_for(std::chrono::seconds(time_to_show));
            auto agora = std::chrono::steady_clock::now();
            std::chrono::duration<double> tempo_decorrido = agora - inicio;

            std::lock_guard<std::mutex> lock(monitor_mutex);
            double taxa = tempo_decorrido.count() > 0 ? total_senhas_verificadas.load() / tempo_decorrido.count() : 0;
            long long total = 123145302310912; // Total possible keys
            float percentage = (total_senhas_verificadas.load() * 100.0) / total;

            std::cout << "\rTime: " << std::fixed << std::setprecision(1) << tempo_decorrido.count() << "s | "
                      << "Keys checked: " << total_senhas_verificadas.load() << " | "
                      << "Rate: " << std::fixed << std::setprecision(1) << taxa << " keys/s "
                      << "Last key: " <<password_to_show;
                      std::cout.flush();
        }
    }

    void monitorBase_key()
    {
      while (!chaveEncontrada.load()) {
          std::cout<<"\rCurrent key: " <<password_to_show;
          std::cout.flush();
      }
      std::cout<<"\n";
    }

    void buscarEnderecoX(const std::string& targetAddress, const std::string& templateKey,int threadId) {
        auto targetBytes = hexToBytes(targetAddress);
        secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
        uint32_t state = static_cast<uint32_t>(threadId);


        while (!chaveEncontrada.load()) {
            auto privateKey = generateRandomKey(templateKey);
            auto privateKeyBytes = hexToBytes(privateKey);

            auto generatedAddress = generateBitcoinAddress(privateKeyBytes, ctx);
            total_senhas_verificadas++;
            password_to_show = privateKey;

            if (generatedAddress == targetBytes) {
                std::lock_guard<std::mutex> lock(monitor_mutex);
                chaveEncontrada.store(true);
                //std::cout <<"\033[33m--------------------------------------------------------------------------------------------\033[0m\n";
                std::cout<<"\n";
                std::cout << "\033[32m\nKey found by thread " << threadId << ": " << privateKey << "\033[0m\n";
                //std::cout <<"\033[33m--------------------------------------------------------------------------------------------\033[0m\n";
                save(privateKey);
            }
        }

        secp256k1_context_destroy(ctx);
    }


    void start(const std::string& targetAddress, const std::string& templateKey, int numThreads, int time_s, const std::vector<int>& id,int bitNumber, bool base_key, bool bitSearch) {
      // Declara o monitorThread fora do escopo do if/else
      std::thread monitorThread;

      // Inicia o monitor de status em uma thread separada
      if (base_key) {
          monitorThread = std::thread(&Secp::monitorBase_key, this);
      } else {
          monitorThread = std::thread(&Secp::monitorStatus, this);
      }

      time_to_show = time_s;
      indices = id;

      // Cria threads para buscar o endereço
      std::vector<std::thread> threads;

        for (int i = 0; i < numThreads; ++i) {
            threads.emplace_back(&Secp::buscarEnderecoX, this, targetAddress, templateKey, i);
        }
      


      // Aguarda todas as threads de busca terminarem
      for (auto& t : threads) {
          t.join();
      }

      // Finaliza o monitor de status
      if (monitorThread.joinable()) {
          monitorThread.join();
      }
  }


};

int main(int argc, char** argv) {
    Secp secp;
    std::string address, keyTemplate;
    int timeInterval = 30;
    int thread_num = 1;
    int bit_num = -1;
    int opt;
    while ((opt = getopt(argc, argv, "ha:k:t:s:b:")) != -1) {
        switch (opt) {
            case 'h':
                secp.help();
                return 0;
            case 'a':
                address = optarg;
                break;
            case 'b':
                bit_num = std::atoi(optarg);
                break;
            case 'k':
                keyTemplate = optarg;
                break;
            case 's':
                timeInterval = std::atoi(optarg);
                break;
            case 't':
                thread_num = std::atoi(optarg);
                break;
            default:
                secp.help();
                return 1;
        }
    }
    bool bits = false;
    if(bit_num !=-1)
    {
        bits=true;
    }
    if ((address.empty() || keyTemplate.empty()) && !bits) {
        secp.help();
        return 1;
    }


    std::vector<int> indices;
    //indices.reserve(keyTemplate.size()/2);
    int countX = 0;
    for (int i = 0; i < keyTemplate.size();i++)
    {

      if (keyTemplate[i] == 'x')
      {
        countX+=1;

        indices.push_back(i);

      }
    }
    if (bits){
      std::cout << "[+] Buscando por --->  "<< address <<std::endl;
      std::cout << "[+] "<<bit_num <<" bits"<<std::endl;
      #include<cmath>
      std::cout <<"[+] Total de chaves -> "<<(pow(2,bit_num)-pow(2,bit_num-1))<<std::endl;

    }else{
      std::cout << "[+] Buscando por --->  "<< address <<std::endl;
      std::cout <<"[+] # bits"<<std::endl;
      std::cout <<"[+] Total de chaves -> "<<(pow(16,countX))<<std::endl;

    }
    if(timeInterval==0)
    {
      //std::cout << "\033[2J\033[H";
      secp.start(address, keyTemplate, thread_num, timeInterval, indices, bit_num, true, bits);
    }else{
      secp.start(address, keyTemplate, thread_num, timeInterval, indices,bit_num, false, bits);
    }

    return 0;
}
