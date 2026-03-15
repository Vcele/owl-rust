// AWDL version encoding/decoding

pub const AWDL_DEVCLASS_MACOS: u8 = 1;
pub const AWDL_DEVCLASS_IOS: u8 = 2;
pub const AWDL_DEVCLASS_TVOS: u8 = 8;

/// Encode major and minor version into a single byte
pub fn awdl_version(major: u8, minor: u8) -> u8 {
    ((major << 4) & 0xf0) | (minor & 0x0f)
}

/// Extract major version from encoded version byte
pub fn awdl_version_major(version: u8) -> u8 {
    (version >> 4) & 0xf
}

/// Extract minor version from encoded version byte
pub fn awdl_version_minor(version: u8) -> u8 {
    version & 0xf
}

/// Convert encoded version to display string
pub fn awdl_version_to_str(version: u8) -> String {
    format!("{}.{}", awdl_version_major(version), awdl_version_minor(version))
}

/// Convert device class to string
pub fn awdl_devclass_to_str(devclass: u8) -> &'static str {
    match devclass {
        AWDL_DEVCLASS_MACOS => "macOS",
        AWDL_DEVCLASS_IOS => "iOS",
        AWDL_DEVCLASS_TVOS => "tvOS",
        _ => "Unknown",
    }
}
