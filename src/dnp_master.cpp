#include <opendnp3/ConsoleLogger.h>
#include <opendnp3/DNP3Manager.h>
#include <opendnp3/channel/PrintingChannelListener.h>
#include <opendnp3/logging/LogLevels.h>
#include <opendnp3/master/DefaultMasterApplication.h>
#include <opendnp3/master/PrintingCommandResultCallback.h>
#include <opendnp3/master/PrintingSOEHandler.h>

using namespace std;
using namespace opendnp3;

class TestSOEHandler : public ISOEHandler
{
    virtual void BeginFragment(const ResponseInfo& info){};
    virtual void EndFragment(const ResponseInfo& info){};

    virtual void Process(const HeaderInfo& info, const ICollection<Indexed<Binary>>& values) {};
    virtual void Process(const HeaderInfo& info, const ICollection<Indexed<DoubleBitBinary>>& values) {};
    virtual void Process(const HeaderInfo& info, const ICollection<Indexed<Analog>>& values) {};
    virtual void Process(const HeaderInfo& info, const ICollection<Indexed<Counter>>& values) {};
    virtual void Process(const HeaderInfo& info, const ICollection<Indexed<FrozenCounter>>& values) {};
    virtual void Process(const HeaderInfo& info, const ICollection<Indexed<BinaryOutputStatus>>& values) {};
    virtual void Process(const HeaderInfo& info, const ICollection<Indexed<AnalogOutputStatus>>& values) {};
    virtual void Process(const HeaderInfo& info, const ICollection<Indexed<OctetString>>& values) {};
    virtual void Process(const HeaderInfo& info, const ICollection<Indexed<TimeAndInterval>>& values) {};
    virtual void Process(const HeaderInfo& info, const ICollection<Indexed<BinaryCommandEvent>>& values) {};
    virtual void Process(const HeaderInfo& info, const ICollection<Indexed<AnalogCommandEvent>>& values) {};    
    virtual void Process(const HeaderInfo& info, const ICollection<DNPTime>& values) {};
};

int main(int argc, char* argv[])
{
    const auto logLevels = levels::NORMAL | levels::ALL_APP_COMMS;

    DNP3Manager manager(1, ConsoleLogger::Create());

    // Connect via a TCPClient socket to a outstation
    auto channel = manager.AddTCPClient("tcpclient", logLevels, ChannelRetry::Default(), {IPEndpoint("127.0.0.1", 20000)},
                                        "0.0.0.0", PrintingChannelListener::Create());

    MasterStackConfig stackConfig;

    stackConfig.master.responseTimeout = TimeDuration::Seconds(2);
    stackConfig.master.disableUnsolOnStartup = true;

    stackConfig.link.LocalAddr = 1;
    stackConfig.link.RemoteAddr = 10;

    auto master = channel->AddMaster("master",                           // id for logging
                                     PrintingSOEHandler::Create(),       // callback for data processing
                                     DefaultMasterApplication::Create(), // master application instance
                                     stackConfig                         // stack configuration
    );

    auto test_soe_handler = std::make_shared<TestSOEHandler>();

    // do an integrity poll (Class 3/2/1/0) once per minute
    auto integrityScan = master->AddClassScan(ClassField::AllClasses(), TimeDuration::Minutes(1), test_soe_handler);

    // do a Class 1 exception poll every 5 seconds
    auto exceptionScan = master->AddClassScan(ClassField(ClassField::CLASS_1), TimeDuration::Seconds(5), test_soe_handler);

    // Enable the master. This will start communications.
    master->Enable();

    bool channelCommsLoggingEnabled = true;
    bool masterCommsLoggingEnabled = true;

    std::cout << "\n[Master] 0.0.0.0:20000 dinlemede. "
                "Outstation baglantisini bekliyor. Cikmak icin ENTER.\n";
    std::string dummy;
    std::getline(std::cin, dummy);   // Program burada bekler, kapanmaz.

}