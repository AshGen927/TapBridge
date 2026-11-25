use std::{
    io::{BufRead, BufReader},
    mem::size_of,
    net::{TcpListener, TcpStream},
    thread,
    time::Duration,
};

use windows::Win32::UI::Input::KeyboardAndMouse::{
    INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBD_EVENT_FLAGS, KEYBDINPUT, KEYEVENTF_KEYUP,
    KEYEVENTF_UNICODE, MOUSE_EVENT_FLAGS, MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP,
    MOUSEEVENTF_MOVE, MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP, MOUSEEVENTF_WHEEL, MOUSEINPUT,
    SendInput, VIRTUAL_KEY,
};

const LISTEN_ADDRESS: &str = "127.0.0.1:7878";
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

fn main() {
    println!("TapBridge Windows agent prototype v0.4");
    println!("Listening only on {LISTEN_ADDRESS}");
    println!("Type 'help' from a local client to see accepted commands.");

    let listener = TcpListener::bind(LISTEN_ADDRESS)
        .expect("Could not bind localhost test port. Is another agent already running?");

    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => handle_client(stream),
            Err(error) => eprintln!("Incoming connection error: {error}"),
        }
    }
}

fn handle_client(stream: TcpStream) {
    let peer = stream.peer_addr().ok();
    println!("Local test client connected: {peer:?}");

    let reader = BufReader::new(stream);

    for line in reader.lines() {
        match line {
            Ok(command) => handle_command(command.trim()),
            Err(error) => {
                eprintln!("Could not read command: {error}");
                break;
            }
        }
    }

    println!("Local test client disconnected: {peer:?}");
}

fn handle_command(command: &str) {
    if let Some(text) = command.strip_prefix("text ") {
        if text.is_empty() {
            eprintln!("Text command cannot be empty. Use: text <message>");
        } else if send_text(text) {
            println!(
                "Sent {} character(s) as keyboard input",
                text.chars().count()
            );
        }
        return;
    }

    let parts: Vec<&str> = command.split_whitespace().collect();

    match parts.as_slice() {
        ["move", dx, dy] => match (dx.parse::<i32>(), dy.parse::<i32>()) {
            (Ok(dx), Ok(dy)) => {
                if send_relative_mouse_move(dx, dy) {
                    println!("Mouse moved by dx={dx}, dy={dy}");
                }
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
    println!("  scroll <notches>      Example: scroll 3 or scroll -3");
    println!("  text <message>        Example: text Hello from TapBridge");
    println!(
        "  key <name>            Names: enter, escape, tab, backspace, delete, left, right, up, down"
    );
    println!(
        "  combo <modifier> <key> Examples: combo ctrl a, combo ctrl c, combo ctrl v, combo alt tab"
    );
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
        _ => None,
    }
}

fn make_mouse_input(dx: i32, dy: i32, flags: MOUSE_EVENT_FLAGS, mouse_data: u32) -> INPUT {
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
    // Modifier goes down first and is always released last.
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
        // Send one Unicode character at a time. A very small delay improves
        // reliability in normal desktop applications such as Notepad.
        let inputs = [
            make_unicode_input(unit, false),
            make_unicode_input(unit, true),
        ];

        if !send_inputs(&inputs) {
            return false;
        }

        thread::sleep(Duration::from_millis(8));
    }

    true
}
