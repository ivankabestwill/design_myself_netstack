
/// all the configuration store here

pub type CONFIG_FLAGS_TYPE = u64;

pub const CONFIG_FLAGS_NONE: CONFIG_FLAGS_TYPE = 0;
pub const CONFIG_FLAGS_CHECKSUM_VALIDATION: CONFIG_FLAGS_TYPE = 1<<0;

// only save config about tcp reassembles
pub struct Config{
    pub tcp_assemble_depth: u32,
    pub detect_enable: bool,
    pub flags: CONFIG_FLAGS_TYPE,
    pub mid_stream: bool,
    pub async_oneside: bool,
}

pub const tcp_assem_config: Config = Config{
    tcp_assemble_depth: 1024*1024, // 1Mbytes per stream, follow suricata
    detect_enable: true,
    flags: CONFIG_FLAGS_NONE,
    mid_stream: true,  // default true, follow suricata.
    async_oneside: false, // default false, follow suricata.
};

