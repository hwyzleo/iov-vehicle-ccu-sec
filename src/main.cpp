#include <iostream>
#include <signal.h>
#include <unistd.h>
#include "config_loader.h"
#include "sec_someip_service.h"

static volatile bool running = true;

void signalHandler(int signum) {
    running = false;
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    std::cout << "CGW-SEC Service starting..." << std::endl;

    try {
        // Load configuration
        auto secConfig = ConfigLoader::loadSecConfig("config/sec_config.yaml");
        auto someipConfig = ConfigLoader::loadSomeipConfig("config/someip_config.yaml");
        auto seHsmConfig = ConfigLoader::loadSeHsmConfig("config/se_hsm_config.yaml");

        // Initialize SOME/IP service
        SecSomeipService service(secConfig, someipConfig, seHsmConfig);
        service.start();

        std::cout << "CGW-SEC Service started successfully" << std::endl;

        while (running) {
            sleep(1);
        }

        service.stop();
        std::cout << "CGW-SEC Service stopped" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "CGW-SEC Service failed: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
