// OWL daemon entry point
//
// Translates daemon/owl.c, replacing getopt with clap and libev with tokio.

mod daemon;

use awdl::channel::AwdlChan;
use clap::Parser;

#[cfg(unix)]
fn daemonize() {
    use std::process;
    unsafe {
        // First fork
        let pid = libc::fork();
        if pid < 0 {
            eprintln!("fork() failed");
            process::exit(1);
        }
        if pid > 0 {
            process::exit(0); // parent exits
        }
        if libc::setsid() < 0 {
            eprintln!("setsid() failed");
            process::exit(1);
        }
        // Second fork
        let pid = libc::fork();
        if pid < 0 {
            eprintln!("fork() failed");
            process::exit(1);
        }
        if pid > 0 {
            process::exit(0);
        }
        libc::umask(0);
        let root = b"/\0";
        libc::chdir(root.as_ptr() as *const _);
        // Close all open file descriptors
        let max_fd = libc::sysconf(libc::_SC_OPEN_MAX);
        for fd in (0..max_fd).rev() {
            libc::close(fd as i32);
        }
    }
}

/// Open Wireless Link — open AWDL implementation
#[derive(Parser, Debug)]
#[command(name = "owl", author, about)]
struct Cli {
    /// Wireless interface to use (required)
    #[arg(short = 'i', long = "interface")]
    wlan: String,

    /// Host TAP interface name (default: awdl0)
    #[arg(short = 'h', long = "host", default_value = "awdl0")]
    host: String,

    /// WiFi channel to use (6, 44, or 149)
    #[arg(short = 'c', long = "channel", default_value_t = 6)]
    channel: u32,

    /// Run as a daemon
    #[arg(short = 'D', long = "daemon")]
    daemonize: bool,

    /// Dump unknown frames to failed.pcap
    #[arg(short = 'd', long = "dump")]
    dump: bool,

    /// Disable RSSI filtering
    #[arg(short = 'f', long = "no-rssi-filter")]
    no_rssi_filter: bool,

    /// Skip setting monitor mode (useful for debugging)
    #[arg(short = 'N', long = "no-monitor-mode")]
    no_monitor_mode: bool,

    /// Increase verbosity (can be repeated)
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    verbose: u8,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Initialise logger; verbosity level maps to log::LevelFilter.
    let log_level = match cli.verbose {
        0 => log::LevelFilter::Info,
        1 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    };
    env_logger::Builder::new()
        .filter_level(log_level)
        .init();

    // Print the OWL banner (matches the C implementation)
    println!(
        "              .oOXWMMMMWXOx:\n\
         .oOOOx:'''''''''''':OOOx:\n\
         oXOo'      ........      ':OXx.\n\
              .oOOO''''''''''OOOo.\n\
           oXOo'                'oOO:\n\
                :oOOOOXXXXOOOOo:.\n\
             oXO:'            ':OXo\n\
                 .:xOXXXXXXOx:.\n\
             .xXMMMMMMMMMMMMMMMMXx.\n\
     'XWWWWWWMMMMMMMMMMMMMMMMMMMMMMWWWWWWX'\n\
       oWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWo\n\
        OMMMMMMWWMMMMMMMMMMMMMMWWWMMMMMO\n\
       OMMWx'      'xWMMMMWx'      'oXMMO\n\
      :MW:            oMMx            'WM:\n\
      XM'    .xOOo.    :o     .xOOo.    WX\n\
      WX    :MMMMMX          :MMMMMX    xW\n\
      XW    'WMMMMX   .xx.   'WMMMWX    XX\n\
      'Wx    'xWMx'   OMMO    'xWMx'   xM'\n\
       'XX:           'XX'           :XX'\n\
         'xXOx:..................:xXWx'\n\
            'xXMMMMMMMMMMMMMMMMMMWO'\n\
\n\
               Open Wireless Link\n\
\n\
               https://owlink.org\n"
    );

    if cli.daemonize {
        #[cfg(unix)]
        daemonize();
        #[cfg(not(unix))]
        {
            eprintln!("Daemonize not supported on this platform");
            std::process::exit(1);
        }
    }

    let chan = match cli.channel {
        6   => AwdlChan::opclass_6(),
        44  => AwdlChan::opclass_44(),
        149 => AwdlChan::opclass_149(),
        n   => {
            eprintln!("Unsupported channel {} (use 6, 44, or 149)", n);
            std::process::exit(1);
        }
    };

    let dump_path = if cli.dump {
        Some("failed.pcap".to_string())
    } else {
        None
    };

    let mut state = match daemon::core::awdl_init(&cli.wlan, &cli.host, chan, dump_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("could not initialize core: {e}");
            std::process::exit(1);
        }
    };

    state.awdl.filter_rssi = !cli.no_rssi_filter;
    state.io.wlan_no_monitor_mode = cli.no_monitor_mode;

    if state.io.wlan_ifindex != 0 {
        let a = &state.io.if_ether_addr;
        log::info!(
            "WLAN device: {} (addr {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x})",
            state.io.wlan_ifname, a[0], a[1], a[2], a[3], a[4], a[5]
        );
    }
    if state.io.host_ifindex != 0 {
        log::info!("Host device: {}", state.io.host_ifname);
    }

    daemon::core::run(state).await;
}
