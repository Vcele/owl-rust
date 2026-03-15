// OWL daemon entry point

use awdl::channel::AwdlChan;
use awdl::state::{AwdlState, clock_time_us};
use awdl::version::awdl_version_to_str;

fn main() {
    // Initialize a basic logger
    env_logger::init();

    let self_addr: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    let hostname = "owl-node";
    let chan = AwdlChan::opclass_6();
    let now = clock_time_us();

    let state = AwdlState::new(hostname, self_addr, chan, now);

    println!("OWL AWDL node started");
    println!("  Self address : {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        state.self_address[0], state.self_address[1], state.self_address[2],
        state.self_address[3], state.self_address[4], state.self_address[5]);
    println!("  Hostname     : {}", state.name);
    println!("  AWDL version : {}", awdl_version_to_str(state.version));
}
