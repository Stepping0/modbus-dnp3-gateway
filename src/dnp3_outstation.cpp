#include <opendnp3/ConsoleLogger.h>
#include <opendnp3/DNP3Manager.h>
#include <opendnp3/channel/PrintingChannelListener.h>
#include <opendnp3/logging/LogLevels.h>
#include <opendnp3/outstation/DefaultOutstationApplication.h>
#include <opendnp3/outstation/IUpdateHandler.h>
#include <opendnp3/outstation/SimpleCommandHandler.h>
#include <opendnp3/outstation/UpdateBuilder.h>

#include <iostream>
#include <string>
#include <thread>

#include <fstream>
#include <sstream>
#include <map>
#include <cstdint>

#include "../include/nlohmann/json.hpp" 

using namespace std;
using namespace opendnp3;
using json = nlohmann::json;

json load_modbus_json(const std::string& path)
{
    std::ifstream file(path);
    if (!file.is_open()) {
        std::cerr << "JSON dosyası açılamadı: " << path << std::endl;
        return {};
    }

    json j;
    try {
        file >> j;
    } catch (const std::exception& e) {
        std::cerr << "JSON parse hatası: " << e.what() << std::endl;
    }

    return j;
}

DatabaseConfig ConfigureDatabase()
{
    DatabaseConfig config(10); // 10 of each type with default settings

    config.analog_input[0].clazz = PointClass::Class2;
    config.analog_input[0].svariation = StaticAnalogVariation::Group30Var5;
    config.analog_input[0].evariation = EventAnalogVariation::Group32Var7;
            
    return config;
}

std::map<uint16_t, std::pair<std::string, int>> load_point_map(const std::string& filename)
{
    std::map<uint16_t, std::pair<std::string, int>> mapping;
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Mapping dosyası açılamadı: " << filename << std::endl;
        return mapping;
    }

    auto trim = [](std::string& s){
        const char* ws = " \t\r\n";
        s.erase(0, s.find_first_not_of(ws));
        s.erase(s.find_last_not_of(ws) + 1);
    };

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#' || line[0] == ';') continue;
        if (auto pos = line.find(';'); pos != std::string::npos) line = line.substr(0, pos);

        auto eq = line.find('=');
        if (eq == std::string::npos) { std::cerr << "Satırda '=' yok: " << line << "\n"; continue; }

        std::string key = line.substr(0, eq);
        std::string val = line.substr(eq + 1);
        trim(key); trim(val);

        uint16_t modbus_addr = static_cast<uint16_t>(std::stoi(key));

        auto comma = val.find(',');
        if (comma == std::string::npos) { std::cerr << "Virgül yok: " << line << "\n"; continue; }

        std::string type = val.substr(0, comma);
        std::string idxs = val.substr(comma + 1);
        trim(type); trim(idxs);

        int dnp_index = std::stoi(idxs);
        mapping[modbus_addr] = {type, dnp_index};
    }
    return mapping;
}


struct State
{
    uint32_t count = 0;
    double value = 0;
    bool binary = false;
    DoubleBit dbit = DoubleBit::DETERMINED_OFF;
    uint8_t octetStringValue = 1;
};

auto app = DefaultOutstationApplication::Create();

void AddUpdates(UpdateBuilder& builder, State& state, const std::string& arguments);

int main(int  argc, char *argv[])
{
    //logLevel
    const auto logLevels = levels::NORMAL | levels::ALL_COMMS;

    //interraction with stack , allocating a single thread to pool- it is a single outstation
    DNP3Manager manager (1,ConsoleLogger::Create());

    //tcp server (listener)
    auto channel = shared_ptr<IChannel>(nullptr);
    try
    {
        channel=manager.AddTCPServer("server", logLevels, ServerAcceptMode::CloseExisting, IPEndpoint("0.0.0.0", 20000),
                                       PrintingChannelListener::Create());
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
        return 1;
    }
    
    auto point_map = load_point_map("../mapping/point_map.conf");

    // Test: çıktı ver
    for (const auto& entry : point_map) {
        std::cout << "Modbus " << entry.first << " → DNP3 "
                  << entry.second.first << " " << entry.second.second << std::endl;
    }

    OutstationStackConfig config(ConfigureDatabase());
    config.outstation.eventBufferConfig = EventBufferConfig::AllTypes(100);
    config.outstation.params.allowUnsolicited = true;
    config.link.LocalAddr = 10;
    config.link.RemoteAddr = 1;
    config.link.KeepAliveTimeout = TimeDuration::Max();

    auto outstation = channel->AddOutstation(
        "outstation",
        SuccessCommandHandler::Create(),
        app,
        config
    );
    outstation->Enable();

    auto json_data = load_modbus_json("../json_kayit/modbus_output.json");

    auto to_absolute_mb_addr = [](int fc, uint16_t start, size_t offset)->uint16_t {
    
    switch (fc) {
        case 1:  return static_cast<uint16_t>(1     + start + offset);   // Coils
        case 2:  return static_cast<uint16_t>(10001 + start + offset);   // Discrete Inputs
        case 3:  return static_cast<uint16_t>(40001 + start + offset);   // Holding Registers
        case 4:  return static_cast<uint16_t>(30001 + start + offset);   // Input Registers
        default: return static_cast<uint16_t>(start + offset);           // fallback
    }
    };

    for (const auto& entry : json_data)
    {
    // Sadece değer içeren kayıtları işle
    if (!(entry.contains("record_type") && entry["record_type"] == "values"))
        continue;

    // Güvenli okuma
    int fc = entry.value("function_code", 0);
    uint16_t start = entry.value("start_address", 0);

    if (!entry.contains("values") || !entry["values"].is_array())
        continue;

    const auto& arr = entry["values"];
    for (size_t i = 0; i < arr.size(); ++i)
    {
        // JSON’daki sayı türünü güvenli al
        double val = 0.0;
        const auto& jv = arr[i];
        if (jv.is_number_float())       val = jv.get<double>();
        else if (jv.is_number_integer())val = static_cast<double>(jv.get<long long>());
        else if (jv.is_string())        { try { val = std::stod(jv.get<std::string>()); } catch (...) { continue; } }
        else continue;

        uint16_t modbus_addr = to_absolute_mb_addr(fc, start, i);

        // Map’te karşılığı var mı?
        auto it = point_map.find(modbus_addr);
        if (it == point_map.end()) {
            std::cout << "[MAP YOK] Modbus " << modbus_addr << " için eşleme bulunamadı.\n";
            continue;
        }

        const auto& [type, index] = it->second;

        UpdateBuilder builder;
        if (type == "Analog") {
            builder.Update(Analog(val), index);
        } else if (type == "Binary") {
            builder.Update(Binary(val > 0.5), index);
        } else {
            std::cout << "[TIP BILINMIYOR] " << type << " @ " << modbus_addr << "\n";
            continue;
        }

        outstation->Apply(builder.Build());
    }

    std::cout << "\n[OUTSTATION] 0.0.0.0:20000 dinlemede. "
                "Master baglantisini bekliyor. Cikmak icin ENTER.\n";
    std::string dummy;
    std::getline(std::cin, dummy);   
    }
}