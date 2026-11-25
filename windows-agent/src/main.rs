use std::{
    env,
    error::Error,
    fs::File,
    io::{BufRead, BufReader, Write},
    mem::size_of,
    net::{TcpListener, TcpStream},
    sync::Arc,
    thread,
    time::Duration,
};

use rand::{rngs::OsRng, RngCore};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    ServerConfig, ServerConnection, StreamOwned,
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use windows::Win32::UI::Input::KeyboardAndMouse::{
    SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBD_EVENT_FLAGS, KEYBDINPUT,
    KEYEVENTF_KEYUP, KEYEVENTF_UNICODE, MOUSE_EVENT_FLAGS, MOUSEEVENTF_LEFTDOWN,
    MOUSEEVENTF_LEFTUP, MOUSEEVENTF_MOVE, MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP,
    MOUSEEVENTF_WHEEL, MOUSEINPUT, VIRTUAL_KEY,
};

const LOOPBACK_ADDRESS: &str = "127.0.0.1:7878";
const CERTIFICATE_PATH: &str = "certs/cert.pem";
const PRIVATE_KEY_PATH: &str = "certs/cert.key.pem";
const WHEEL_DELTA: i32 = 120;

const VK_BACKSPACE: VIRTUAL_KEY = VIRTUAL_KEY(0x08);
const VK_TAB: VIRTUAL_KEY = VIRTUAL_KEY(0x09);
const VK_ENTER: VIRTUAL_KEY = VIRTUAL_KEY(0x0D);
const VK_SHIFT: VIRTUAL_KEY = VIRTUAL_KEY(0x10);
const VK_CONTROL: VIRTUAL_KEY = VIRTUAL_KEY(0x11);
const VK_ALT: VIRTUAL_KEY = VIRTUAL_KEY(0x12);
const VK_ESCAPE: VIRTUAL_KEY = VIRTUAL_KEY(0x1B);
const VK_LEFT: VIRTUAL_KEY = VIRTUAL_KEY(0x25);
const VK_UP: VIRTUAL_KEY = VIRTUAL_KEY(0x26);
const VK_RIGHT: VIRTUAL_KEY = VIRTUAL_KEY(0x27);
const VK_DOWN: VIRTUAL_KEY = VIRTUAL_KEY(0x28);
const VK_DELETE: VIRTUAL_KEY = VIRTUAL_KEY(0x2E);
const VK_VOLUME_MUTE: VIRTUAL_KEY = VIRTUAL_KEY(0xAD);
const VK_VOLUME_DOWN: VIRTUAL_KEY = VIRTUAL_KEY(0xAE);
const VK_VOLUME_UP: VIRTUAL_KEY = VIRTUAL_KEY(0xAF);
const VK_MEDIA_NEXT_TRACK: VIRTUAL_KEY = VIRTUAL_KEY(0xB0);
const VK_MEDIA_PREV_TRACK: VIRTUAL_KEY = VIRTUAL_KEY(0xB1);
const VK_MEDIA_PLAY_PAUSE: VIRTUAL_KEY = VIRTUAL_KEY(0xB3);

#[derive(Clone, Copy)]
enum PairingCodeMode {
    Strong,
    EasyDevelopment,
}

#[derive(Clone, Copy)]
enum LocalTransport {
    WiFi,
    UsbTether,
}

impl LocalTransport {
    fn label(self) -> &'static str {
        match self {
            Self::WiFi => "WI-FI LAN",
            Self::UsbTether => "USB TETHER",
        }
    }
}

fn main() {
    // Pick exactly one Rustls cryptographic provider. This keeps TLS configuration
    // explicit instead of relying on feature-dependent automatic selection.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Could not install the Rustls cryptographic provider");

    let args: Vec<String> = env::args().collect();

    match args.as_slice() {
        [_program] => run_loopback_agent(),
        [_program, flag, address] if flag == "--lan" => {
            run_secure_local_agent(address, PairingCodeMode::Strong, LocalTransport::WiFi)
        }
        [_program, flag, address] if flag == "--lan-easy" => {
            run_secure_local_agent(address, PairingCodeMode::EasyDevelopment, LocalTransport::WiFi)
        }
        [_program, flag, address] if flag == "--usb" => {
            run_secure_local_agent(address, PairingCodeMode::Strong, LocalTransport::UsbTether)
        }
        [_program, flag, address] if flag == "--usb-easy" => {
            run_secure_local_agent(address, PairingCodeMode::EasyDevelopment, LocalTransport::UsbTether)
        }
        _ => print_usage(),
    }
}

fn print_usage() {
    println!("TapBridge Windows agent prototype v0.5.8");
    println!();
    println!("Safe localhost-only mode:");
    println!("  cargo run");
    println!();
    println!("Secure LAN mode with a strong 48-character code:");
    println!("  cargo run -- --lan <your-PC-IPv4-address>:7878");
    println!();
    println!("Easy-code Wi-Fi development mode (10 digits; weaker):");
    println!("  cargo run -- --lan-easy <your-PC-Wi-Fi-IPv4-address>:7878");
    println!();
    println!("Offline USB-tether mode (same certificate-pinned TLS protocol):");
    println!("  cargo run -- --usb <your-PC-USB-tether-IPv4-address>:7878");
    println!("  cargo run -- --usb-easy <your-PC-USB-tether-IPv4-address>:7878");
    println!();
    println!("Example:");
    println!("  cargo run -- --usb-easy 192.168.42.164:7878");
    println!();
    println!("LAN mode requires certs/cert.pem and certs/cert.key.pem.");
}

fn run_loopback_agent() {
    println!("TapBridge Windows agent prototype v0.5.8");
    println!("Local test mode: listening only on {LOOPBACK_ADDRESS}");
    println!("Type 'help' from a local client to see accepted commands.");

    let listener = TcpListener::bind(LOOPBACK_ADDRESS)
        .expect("Could not bind localhost test port. Is another agent already running?");

    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => handle_loopback_client(stream),
            Err(error) => eprintln!("Incoming localhost connection error: {error}"),
        }
    }
}

fn run_secure_local_agent(
    address: &str,
    pairing_mode: PairingCodeMode,
    transport: LocalTransport,
) {
    let (tls_config, certificate_fingerprint) = load_tls_config().unwrap_or_else(|error| {
        eprintln!("Could not start secure LAN mode: {error}");
        eprintln!("Expected certificate: {CERTIFICATE_PATH}");
        eprintln!("Expected private key: {PRIVATE_KEY_PATH}");
        eprintln!("Create them using the setup guide before retrying.");
        std::process::exit(1);
    });

    let pairing_code = generate_pairing_code(pairing_mode);
    let listener = TcpListener::bind(address).unwrap_or_else(|error| {
        eprintln!("Could not bind secure LAN address {address}: {error}");
        eprintln!("Check the intended Wi-Fi or USB-tether adapter IPv4 address with ipconfig.");
        std::process::exit(1);
    });

    println!("TapBridge Windows agent prototype v0.5.8");
    println!("SECURE LOCAL {} MODE", transport.label());
    println!("Listening with TLS on {address}");
    println!();
    println!("Enter these values in the TapBridge Android pairing screen:");
    println!("  PC address: {address}");
    println!("  Certificate SHA-256 fingerprint:");
    println!("  {certificate_fingerprint}");
    match pairing_mode {
        PairingCodeMode::Strong => println!("  One-time pairing code:"),
        PairingCodeMode::EasyDevelopment => {
            println!("  Easy development pairing code (10 digits; weaker):")
        }
    }
    println!("  {}", display_pairing_code(&pairing_code, pairing_mode));
    println!();
    println!("The pairing code changes every time the agent starts.");
    println!("Easy mode is only for short private-link tests; use --lan or --usb for the stronger code.");
    if matches!(transport, LocalTransport::UsbTether) {
        println!("USB tether mode is local-only and needs no Wi-Fi or internet connection.");
    }
    println!("Do not share the code or fingerprint. Press Ctrl+C to stop LAN access.");

    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                let config = Arc::clone(&tls_config);
                let code = pairing_code.clone();
                thread::spawn(move || handle_secure_lan_client(stream, config, code));
            }
            Err(error) => eprintln!("Incoming LAN connection error: {error}"),
        }
    }
}

fn load_tls_config() -> Result<(Arc<ServerConfig>, String), Box<dyn Error>> {
    let certificates = load_certificates()?;
    let first_certificate = certificates
        .first()
        .ok_or("No certificate was found in certs/cert.pem")?;
    let fingerprint = sha256_hex(first_certificate.as_ref());
    let private_key = load_private_key()?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)?;

    Ok((Arc::new(config), fingerprint))
}

fn load_certificates() -> Result<Vec<CertificateDer<'static>>, Box<dyn Error>> {
    let certificate_file = File::open(CERTIFICATE_PATH)?;
    let mut reader = BufReader::new(certificate_file);
    let certificates = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;

    if certificates.is_empty() {
        return Err("certs/cert.pem contains no certificate".into());
    }

    Ok(certificates)
}

fn load_private_key() -> Result<PrivateKeyDer<'static>, Box<dyn Error>> {
    let private_key_file = File::open(PRIVATE_KEY_PATH)?;
    let mut reader = BufReader::new(private_key_file);

    rustls_pemfile::private_key(&mut reader)?
        .ok_or_else(|| "certs/cert.key.pem contains no private key".into())
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<String>()
}

fn generate_pairing_code(mode: PairingCodeMode) -> String {
    let mut rng = OsRng;

    match mode {
        PairingCodeMode::Strong => {
            let mut random_bytes = [0_u8; 24];
            rng.fill_bytes(&mut random_bytes);
            random_bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        }
        PairingCodeMode::EasyDevelopment => (0..10)
            .map(|_| random_decimal_digit(&mut rng))
            .collect::<String>(),
    }
}

fn random_decimal_digit(rng: &mut OsRng) -> char {
    // Rejection sampling prevents modulo bias: values 250–255 are discarded.
    loop {
        let mut byte = [0_u8; 1];
        rng.fill_bytes(&mut byte);
        if byte[0] < 250 {
            return char::from(b'0' + (byte[0] % 10));
        }
    }
}

fn display_pairing_code(code: &str, mode: PairingCodeMode) -> String {
    match mode {
        PairingCodeMode::Strong => code.to_owned(),
        PairingCodeMode::EasyDevelopment => format!("{}-{}", &code[..5], &code[5..]),
    }
}

fn handle_loopback_client(stream: TcpStream) {
    let peer = stream.peer_addr().ok();
    println!("Local test client connected: {peer:?}");
    handle_command_stream(BufReader::new(stream));
    println!("Local test client disconnected: {peer:?}");
}

fn handle_secure_lan_client(
    stream: TcpStream,
    tls_config: Arc<ServerConfig>,
    pairing_code: String,
) {
    let peer = stream.peer_addr().ok();

    if let Err(error) = stream.set_read_timeout(Some(Duration::from_secs(12))) {
        eprintln!("Could not set LAN read timeout: {error}");
        return;
    }
    if let Err(error) = stream.set_write_timeout(Some(Duration::from_secs(12))) {
        eprintln!("Could not set LAN write timeout: {error}");
        return;
    }

    let connection = match ServerConnection::new(tls_config) {
        Ok(connection) => connection,
        Err(error) => {
            eprintln!("Could not create TLS connection: {error}");
            return;
        }
    };

    let tls_stream = StreamOwned::new(connection, stream);
    let mut reader = BufReader::new(tls_stream);
    let mut first_line = String::new();

    match reader.read_line(&mut first_line) {
        Ok(0) => return,
        Ok(_) => {}
        Err(error) => {
            eprintln!("TLS handshake or pairing read failed from {peer:?}: {error}");
            return;
        }
    }

    let supplied_code = first_line
        .trim_end_matches(['\r', '\n'])
        .strip_prefix("pair ");

    if !supplied_code.is_some_and(|code| pairing_code_matches(code, &pairing_code)) {
        let _ = reader.get_mut().write_all(b"ERR pairing rejected\n");
        let _ = reader.get_mut().flush();
        eprintln!("Rejected unauthenticated LAN client: {peer:?}");
        return;
    }

    if reader.get_mut().write_all(b"OK paired\n").is_err() || reader.get_mut().flush().is_err() {
        eprintln!("Could not acknowledge paired LAN client: {peer:?}");
        return;
    }

    // The 12-second timeout protects the TLS handshake and pairing exchange.
    // Once pairing succeeds, clear it: a phone may be idle for minutes while
    // the user reads or watches something on the PC.
    if let Err(error) = reader.get_mut().sock.set_read_timeout(None) {
        eprintln!("Could not clear paired-client read timeout: {error}");
        return;
    }
    if let Err(error) = reader.get_mut().sock.set_write_timeout(None) {
        eprintln!("Could not clear paired-client write timeout: {error}");
        return;
    }

    println!("Securely paired LAN client connected: {peer:?}");
    handle_command_stream(reader);
    println!("Secure LAN client disconnected: {peer:?}");
}

fn pairing_code_matches(supplied: &str, expected: &str) -> bool {
    // All generated codes have the same fixed length. The length check avoids
    // comparing differently sized slices; the secret comparison itself is constant-time.
    supplied.len() == expected.len()
        && supplied
            .as_bytes()
            .ct_eq(expected.as_bytes())
            .unwrap_u8()
            == 1
}

#[derive(Default)]
struct HeldMouseButtons {
    left: bool,
    right: bool,
}

impl HeldMouseButtons {
    fn release_all(&mut self) {
        // A network loss or app background must never leave a Windows mouse
        // button held down. This is intentionally best-effort and idempotent.
        if self.left {
            let _ = send_mouse_button(MOUSEEVENTF_LEFTUP);
            self.left = false;
            println!("Released held left button after client disconnect");
        }
        if self.right {
            let _ = send_mouse_button(MOUSEEVENTF_RIGHTUP);
            self.right = false;
            println!("Released held right button after client disconnect");
        }
    }
}

fn handle_command_stream<R: BufRead>(reader: R) {
    let mut held_buttons = HeldMouseButtons::default();

    for line in reader.lines() {
        match line {
            Ok(command) => handle_command(command.trim(), &mut held_buttons),
            Err(error) => {
                eprintln!("Could not read command: {error}");
                break;
            }
        }
    }

    held_buttons.release_all();
}

fn handle_command(command: &str, held_buttons: &mut HeldMouseButtons) {
    if let Some(text) = command.strip_prefix("text ") {
        if text.is_empty() {
            eprintln!("Text command cannot be empty. Use: text <message>");
        } else if send_text(text) {
            println!("Sent {} character(s) as keyboard input", text.chars().count());
        }
        return;
    }

    let parts: Vec<&str> = command.split_whitespace().collect();

    match parts.as_slice() {
        ["move", dx, dy] => match (dx.parse::<i32>(), dy.parse::<i32>()) {
            (Ok(dx), Ok(dy)) => {
                // Pointer motion can arrive at frame rate. Do not write a console
                // line per movement: Windows console output itself causes latency
                // and jitter in a real-time controller loop.
                let _ = send_relative_mouse_move(dx, dy);
            }
            _ => eprintln!("Invalid move command. Use: move <integer dx> <integer dy>"),
        },
        ["click", "left"] => {
            if send_mouse_click(MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP) {
                println!("Left click sent");
            }
        }
        ["click", "right"] => {
            if send_mouse_click(MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP) {
                println!("Right click sent");
            }
        }
        ["button", "left", "down"] => {
            if !held_buttons.left && send_mouse_button(MOUSEEVENTF_LEFTDOWN) {
                held_buttons.left = true;
                println!("Left button down sent");
            }
        }
        ["button", "left", "up"] => {
            if held_buttons.left && send_mouse_button(MOUSEEVENTF_LEFTUP) {
                held_buttons.left = false;
                println!("Left button up sent");
            }
        }
        ["button", "right", "down"] => {
            if !held_buttons.right && send_mouse_button(MOUSEEVENTF_RIGHTDOWN) {
                held_buttons.right = true;
                println!("Right button down sent");
            }
        }
        ["button", "right", "up"] => {
            if held_buttons.right && send_mouse_button(MOUSEEVENTF_RIGHTUP) {
                held_buttons.right = false;
                println!("Right button up sent");
            }
        }
        ["scroll", notches] => match notches.parse::<i32>() {
            Ok(notches) if notches != 0 => {
                if send_scroll(notches) {
                    println!("Scrolled {notches} notch(es)");
                }
            }
            _ => eprintln!("Invalid scroll command. Use: scroll <non-zero integer>"),
        },
        ["key", key] => match named_key(key) {
            Some(virtual_key) => {
                if send_virtual_key(virtual_key) {
                    println!("Sent key: {key}");
                }
            }
            None => eprintln!("Unknown key: {key:?}. Type 'help' for valid keys."),
        },
        ["combo", modifier, key] => match (modifier_key(modifier), named_key(key)) {
            (Some(modifier_virtual_key), Some(key_virtual_key)) => {
                if send_key_combo(modifier_virtual_key, key_virtual_key) {
                    println!("Sent shortcut: {modifier}+{key}");
                }
            }
            (None, _) => eprintln!("Unknown modifier: {modifier:?}. Use ctrl, alt, or shift."),
            (_, None) => eprintln!("Unknown shortcut key: {key:?}. Use a letter or supported key."),
        },
        ["ping"] => {
            // Flutter sends this small authenticated TLS heartbeat while the
            // app is foregrounded. Keep it silent to avoid console overhead.
        }
        ["help"] => print_help(),
        [] => {}
        _ => eprintln!("Rejected unknown command: {command:?}. Type 'help' for valid commands."),
    }
}

fn print_help() {
    println!("Supported commands:");
    println!("  move <dx> <dy>       Example: move 150 0");
    println!("  click left            Sends a left mouse click");
    println!("  click right           Sends a right mouse click");
    println!("  button <side> <state> Examples: button left down, button left up");
    println!("  scroll <notches>      Example: scroll 3 or scroll -3");
    println!("  text <message>        Example: text Hello from TapBridge");
    println!("  key <name>            Names: enter, escape, tab, backspace, delete, left, right, up, down");
    println!("                         Media: volume_mute, volume_up, volume_down, media_play_pause, media_next, media_previous");
    println!("  combo <modifier> <key> Examples: combo ctrl a, combo ctrl c, combo ctrl v, combo alt tab");
    println!("  ping                  Internal mobile keepalive; no input action");
}

fn modifier_key(name: &str) -> Option<VIRTUAL_KEY> {
    match name.to_ascii_lowercase().as_str() {
        "ctrl" | "control" => Some(VK_CONTROL),
        "alt" => Some(VK_ALT),
        "shift" => Some(VK_SHIFT),
        _ => None,
    }
}

fn named_key(name: &str) -> Option<VIRTUAL_KEY> {
    if name.len() == 1 {
        let character = name.chars().next()?;
        if character.is_ascii_alphabetic() {
            return Some(VIRTUAL_KEY(character.to_ascii_uppercase() as u16));
        }
    }

    match name.to_ascii_lowercase().as_str() {
        "backspace" => Some(VK_BACKSPACE),
        "tab" => Some(VK_TAB),
        "enter" => Some(VK_ENTER),
        "escape" | "esc" => Some(VK_ESCAPE),
        "left" => Some(VK_LEFT),
        "up" => Some(VK_UP),
        "right" => Some(VK_RIGHT),
        "down" => Some(VK_DOWN),
        "delete" | "del" => Some(VK_DELETE),
        "volume_mute" | "mute" => Some(VK_VOLUME_MUTE),
        "volume_down" | "vol_down" => Some(VK_VOLUME_DOWN),
        "volume_up" | "vol_up" => Some(VK_VOLUME_UP),
        "media_next" | "next_track" => Some(VK_MEDIA_NEXT_TRACK),
        "media_previous" | "media_prev" | "previous_track" => Some(VK_MEDIA_PREV_TRACK),
        "media_play_pause" | "play_pause" => Some(VK_MEDIA_PLAY_PAUSE),
        _ => None,
    }
}

fn make_mouse_input(
    dx: i32,
    dy: i32,
    flags: MOUSE_EVENT_FLAGS,
    mouse_data: u32,
) -> INPUT {
    INPUT {
        r#type: INPUT_MOUSE,
        Anonymous: INPUT_0 {
            mi: MOUSEINPUT {
                dx,
                dy,
                mouseData: mouse_data,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

fn make_virtual_key_input(key: VIRTUAL_KEY, flags: KEYBD_EVENT_FLAGS) -> INPUT {
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: key,
                wScan: 0,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

fn make_unicode_input(character: u16, key_up: bool) -> INPUT {
    let mut flags = KEYEVENTF_UNICODE;
    if key_up {
        flags |= KEYEVENTF_KEYUP;
    }

    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: VIRTUAL_KEY(0),
                wScan: character,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

fn send_inputs(inputs: &[INPUT]) -> bool {
    let sent = unsafe { SendInput(inputs, size_of::<INPUT>() as i32) };

    if sent != inputs.len() as u32 {
        eprintln!(
            "Windows accepted {sent} of {} input event(s). The action was not completed.",
            inputs.len()
        );
        return false;
    }

    true
}

fn send_relative_mouse_move(dx: i32, dy: i32) -> bool {
    let input = make_mouse_input(dx, dy, MOUSEEVENTF_MOVE, 0);
    send_inputs(&[input])
}

fn send_mouse_click(down: MOUSE_EVENT_FLAGS, up: MOUSE_EVENT_FLAGS) -> bool {
    let inputs = [
        make_mouse_input(0, 0, down, 0),
        make_mouse_input(0, 0, up, 0),
    ];
    send_inputs(&inputs)
}

fn send_mouse_button(flag: MOUSE_EVENT_FLAGS) -> bool {
    let input = make_mouse_input(0, 0, flag, 0);
    send_inputs(&[input])
}

fn send_scroll(notches: i32) -> bool {
    let wheel_delta = notches.saturating_mul(WHEEL_DELTA) as u32;
    let input = make_mouse_input(0, 0, MOUSEEVENTF_WHEEL, wheel_delta);
    send_inputs(&[input])
}

fn send_virtual_key(key: VIRTUAL_KEY) -> bool {
    let inputs = [
        make_virtual_key_input(key, KEYBD_EVENT_FLAGS(0)),
        make_virtual_key_input(key, KEYEVENTF_KEYUP),
    ];
    send_inputs(&inputs)
}

fn send_key_combo(modifier: VIRTUAL_KEY, key: VIRTUAL_KEY) -> bool {
    let inputs = [
        make_virtual_key_input(modifier, KEYBD_EVENT_FLAGS(0)),
        make_virtual_key_input(key, KEYBD_EVENT_FLAGS(0)),
        make_virtual_key_input(key, KEYEVENTF_KEYUP),
        make_virtual_key_input(modifier, KEYEVENTF_KEYUP),
    ];
    send_inputs(&inputs)
}

fn send_text(text: &str) -> bool {
    for unit in text.encode_utf16() {
        let inputs = [
            make_unicode_input(unit, false),
            make_unicode_input(unit, true),
        ];

        if !send_inputs(&inputs) {
            return false;
        }

        // Normal desktop applications can drop a burst of Unicode events.
        thread::sleep(Duration::from_millis(8));
    }

    true
}
