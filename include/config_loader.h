#pragma once

#include <string>

struct SecConfig {
    std::string se_hsm_type;
    int default_security_level;
    int seed_expiration_ms;
    int max_seed_pool_size;
};

struct SomeipConfig {
    int service_id;
    int instance_id;
    int get_seed_method_id;
    int verify_key_method_id;
    int derive_ota_session_method_id;
    int derive_by_uid_method_id;
    int wrap_by_uid_method_id;
};

struct SeHsmConfig {
    std::string type;
    std::string storage_path;
    std::string ota_vehicle_root_key;
    std::string cgw_device_root_key;
    std::string diag_seedkey_secret;
};

class ConfigLoader {
public:
    static SecConfig loadSecConfig(const std::string& path);
    static SomeipConfig loadSomeipConfig(const std::string& path);
    static SeHsmConfig loadSeHsmConfig(const std::string& path);
};
