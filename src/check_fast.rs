use fast_socks5::consts::SOCKS5_CMD_UDP_ASSOCIATE;
use fast_socks5::server::Socks5Socket;

pub fn check() {
    // This is just to check if these exist
    let _ = SOCKS5_CMD_UDP_ASSOCIATE;
}
