# Modbus → DNP3 Gateway

Bu proje, Modbus/TCP trafiğini DNP3 protokolüne dönüştüren bir gateway uygulamasıdır.

## Özellikler

- **Modbus/TCP PCAP Parser**: PCAP dosyalarından Modbus trafiğini analiz ederek JSON formatında çıktı üretir
- **Protocol Gateway**: JSON verilerini DNP3 protokolüne dönüştürür  
- **DNP3 Outstation**: OpenDNP3 kütüphanesi kullanarak DNP3 outstation simülasyonu
- **DNP3 Master**: Test amaçlı DNP3 master uygulaması

## Gereksinimler

### Sistem Gereksinimleri
- CMake (3.10+) 
- GCC/G++ derleyicisi
- Linux/Unix tabanlı işletim sistemi

### Kütüphaneler
- `libpcap-dev` - Paket yakalama için
- OpenDNP3 - DNP3 protokol implementasyonu
- `nlohmann/json` - JSON işleme (single-header)

### Kurulum (Ubuntu/Debian)
```bash
sudo apt update
sudo apt install cmake build-essential libpcap-dev
```

## Derleme

```bash
# Proje dizininde
mkdir -p build && cd build
cmake ..
make -j$(nproc)
```

## Kullanım

### 1. PCAP Dosyasından JSON Çıkarma

```bash
# Demo PCAP dosyasını işle
./build/modbus_pcap2json captures/demo.pcapng

# Çıktı dosyası: json_kayit/modbus_output.json
```

### 2. Nokta Eşleme Konfigürasyonu

`mapping/point_map.conf` dosyasında Modbus adreslerini DNP3 nokta tiplerine eşleyin:

```
# Format: ModbusAddr = DNP3Type, DNP3Index
40001 = Analog, 0
40002 = Analog, 1  
40003 = Analog, 2
10001 = Binary, 0
10002 = Binary, 1
```

**Desteklenen DNP3 Tipleri:**
- `Analog` - Analog Input (30001-39999 → DNP3 AI)
- `Binary` - Binary Input (10001-19999 → DNP3 BI)

### 3. DNP3 Outstation'ı Başlatma

```bash
./build/dnp3_outstation
```

**Konfigürasyon:**
- Listen Adresi: `0.0.0.0:20000`
- Local Address: 10
- Remote Address: 1

### 4. DNP3 Master ile Test

```bash
# Yeni terminal penceresi
./build/dnp3_master
```

**Konfigürasyon:**
- Bağlantı: `127.0.0.1:20000`
- Local Address: 1  
- Remote Address: 10

## Proje Yapısı

```
├── src/                    # Kaynak kodlar
│   ├── modbus_pcap2json.c     # PCAP parser
│   ├── dnp3_outstation.cpp    # DNP3 outstation
│   └── dnp3_master.cpp        # DNP3 master test
├── include/                # Header dosyaları
├── mapping/                # Konfigürasyon dosyaları
│   └── point_map.conf         # Nokta eşleme
├── captures/               # Örnek PCAP dosyaları
├── json_kayit/            # Parser çıktıları
├── build/                 # Derlenmiş dosyalar
└── CMakeLists.txt         # CMake konfigürasyonu
```

## Veri Akışı

1. **Modbus PCAP** → `modbus_pcap2json` → **JSON dosyası**
2. **JSON + Eşleme** → `dnp3_outstation` → **DNP3 Outstation**  
3. **DNP3 Master** → Outstation'dan veri okuma

## Güvenlik Uyarıları

⚠️ **Dikkat**: Bu araç yalnızca test ve geliştirme amaçlıdır.

- Üretim ortamında kullanmadan önce kapsamlı güvenlik testleri yapın
- İzole test ağlarında kullanın
- Firewall kurallarını uygun şekilde yapılandırın

## Notlar

- Outstation link adresleri varsayılan: Local=10, Remote=1 (Master'da tersi olmalı)
- Üretim öncesi yalnızca izole test ortamlarında kullanın
