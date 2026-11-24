//! ssenc command line interface. See SPEC.md section 7.

use ssenc::{decrypt, encrypt, inspect, rekey, EncryptOptions, Error, ErrorKind, Key, Mode, RekeyOptions, VERSION};
use std::io::{IsTerminal, Read, Write};

const IMPL: &str = "rust";

const USAGE: &str = "usage:
  ssenc encrypt [--mode lines|blob|auto] [--no-preserve-ws] [--pad N] [--chunk N] [--kdf PROFILE]
                [--seal] [--previous FILE | --fresh] KEYS [-i IN] [-o OUT]
  ssenc decrypt KEY [-i IN] [-o OUT]
  ssenc rekey   KEY NEWKEYS [--kdf PROFILE] [--rewrap-only] [-i IN] [-o OUT]
  ssenc inspect [-i IN]
  ssenc --version

  KEY/KEYS  --password-file F | env SSENC_PASSWORD | --ssh-key PUBFILE_OR_FINGERPRINT
  NEWKEYS   --new-password-file F | env SSENC_NEW_PASSWORD | --new-ssh-key PUBFILE_OR_FINGERPRINT";

/// Every failure of the command is one of the four ssenc error kinds, so every failure has
/// one of the documented exit codes (1 to 4).
type Failure = Error;

fn usage(msg: impl AsRef<str>) -> Failure {
    Error::new(ErrorKind::Usage, format!("{}\n{}", msg.as_ref(), USAGE))
}

fn plain_usage(msg: String) -> Failure {
    Error::new(ErrorKind::Usage, msg)
}

fn read_password_file(path: &str) -> Result<Vec<u8>, Failure> {
    let mut b = std::fs::read(path).map_err(|e| plain_usage(format!("cannot read password file {path}: {e}")))?;
    if b.last() == Some(&b'\n') {
        b.pop();
    }
    if b.last() == Some(&b'\r') {
        b.pop();
    }
    Ok(b)
}

fn ssh_key_arg(arg: &str) -> Result<Key, Failure> {
    if arg.starts_with("SHA256:") {
        return Ok(Key::ssh_fingerprint(arg));
    }
    let bytes = std::fs::read(arg).map_err(|e| plain_usage(format!("cannot read ssh public key file {arg}: {e}")))?;
    Ok(Key::ssh_public_key(String::from_utf8_lossy(&bytes)))
}

fn env_bytes(name: &str) -> Option<Vec<u8>> {
    let v = std::env::var_os(name)?;
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        Some(v.into_vec())
    }
    #[cfg(not(unix))]
    {
        Some(v.to_string_lossy().into_owned().into_bytes())
    }
}

#[cfg(unix)]
mod tty {
    /// Switches echo and line editing of stdin off; restores the old state when dropped.
    pub struct Raw(libc::termios);

    impl Raw {
        pub fn enter() -> std::io::Result<Raw> {
            // SAFETY: termios is plain data; tcgetattr fills it in before it is read.
            unsafe {
                let mut old: libc::termios = std::mem::zeroed();
                if libc::tcgetattr(libc::STDIN_FILENO, &mut old) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let mut raw = old;
                raw.c_lflag &= !(libc::ECHO | libc::ICANON | libc::ISIG);
                raw.c_cc[libc::VMIN] = 1;
                raw.c_cc[libc::VTIME] = 0;
                if libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &raw) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(Raw(old))
            }
        }
    }

    impl Drop for Raw {
        fn drop(&mut self) {
            // SAFETY: restores the attributes read in enter().
            unsafe {
                libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.0);
            }
        }
    }
}

#[cfg(windows)]
mod tty {
    use std::ffi::c_void;

    const STD_INPUT_HANDLE: u32 = -10i32 as u32;
    const ENABLE_PROCESSED_INPUT: u32 = 0x0001;
    const ENABLE_LINE_INPUT: u32 = 0x0002;
    const ENABLE_ECHO_INPUT: u32 = 0x0004;

    #[link(name = "kernel32")]
    extern "system" {
        fn GetStdHandle(which: u32) -> *mut c_void;
        fn GetConsoleMode(handle: *mut c_void, mode: *mut u32) -> i32;
        fn SetConsoleMode(handle: *mut c_void, mode: u32) -> i32;
    }

    /// Switches echo and line editing of the console off; restores the old mode when dropped.
    pub struct Raw(*mut c_void, u32);

    impl Raw {
        pub fn enter() -> std::io::Result<Raw> {
            // SAFETY: plain Win32 calls with a valid out pointer.
            unsafe {
                let handle = GetStdHandle(STD_INPUT_HANDLE);
                let mut old = 0u32;
                if GetConsoleMode(handle, &mut old) == 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let raw = old & !(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT);
                if SetConsoleMode(handle, raw) == 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(Raw(handle, old))
            }
        }
    }

    impl Drop for Raw {
        fn drop(&mut self) {
            // SAFETY: restores the mode read in enter().
            unsafe {
                SetConsoleMode(self.0, self.1);
            }
        }
    }
}

#[cfg(not(any(unix, windows)))]
mod tty {
    pub struct Raw;
    impl Raw {
        pub fn enter() -> std::io::Result<Raw> {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "no terminal support on this platform",
            ))
        }
    }
}

fn prompt_password(label: &str) -> Result<Vec<u8>, Failure> {
    let mut stderr = std::io::stderr();
    let _ = stderr.write_all(label.as_bytes());
    let _ = stderr.flush();
    let raw = tty::Raw::enter().map_err(|e| plain_usage(format!("cannot read the password from the terminal: {e}")))?;
    let mut bytes = Vec::new();
    let mut stdin = std::io::stdin().lock();
    let mut interrupted = false;
    loop {
        let mut c = [0u8; 1];
        match stdin.read(&mut c) {
            Ok(1) => {}
            Ok(_) => break,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
        match c[0] {
            b'\r' | b'\n' => break,
            3 => {
                interrupted = true;
                break;
            }
            127 | 8 => {
                bytes.pop();
            }
            c => bytes.push(c),
        }
    }
    drop(raw);
    let _ = stderr.write_all(b"\n");
    if interrupted {
        return Err(plain_usage("interrupted".to_string()));
    }
    Ok(bytes)
}

#[derive(Default)]
struct Args {
    in_path: Option<String>,
    out_path: Option<String>,
    pw_file: Option<String>,
    new_pw_file: Option<String>,
    previous: Option<String>,
    fresh: bool,
    rewrap_only: bool,
    kdf: Option<String>,
    ssh_keys: Vec<String>,
    new_ssh_keys: Vec<String>,
    opts: EncryptOptions,
}

fn parse_args(cmd: &str, argv: &[String]) -> Result<Args, Failure> {
    let mut a = Args::default();
    let mut i = 0;
    while i < argv.len() {
        let opt = argv[i].as_str();
        let mut value = || -> Result<String, Failure> {
            if i + 1 >= argv.len() {
                return Err(usage(format!("option {opt} needs a value")));
            }
            i += 1;
            Ok(argv[i].clone())
        };
        let only = |cmds: &[&str]| -> Result<(), Failure> {
            if cmds.contains(&cmd) {
                Ok(())
            } else {
                Err(usage(format!("option {opt} is not valid for '{cmd}'")))
            }
        };
        let int = |v: String| -> Result<u64, Failure> {
            let ok = v == "0" || (!v.is_empty() && !v.starts_with('0') && v.bytes().all(|c| c.is_ascii_digit()));
            if !ok {
                return Err(usage(format!("option {opt} needs a non-negative integer")));
            }
            // Anything that does not fit is out of every valid range anyway.
            Ok(v.parse().unwrap_or(u64::MAX))
        };
        const KEYED: &[&str] = &["encrypt", "decrypt", "rekey"];
        match opt {
            "-i" => a.in_path = Some(value()?),
            "-o" => {
                only(KEYED)?;
                a.out_path = Some(value()?);
            }
            "--password-file" => {
                only(KEYED)?;
                a.pw_file = Some(value()?);
            }
            "--ssh-key" => {
                only(KEYED)?;
                a.ssh_keys.push(value()?);
            }
            "--new-password-file" => {
                only(&["rekey"])?;
                a.new_pw_file = Some(value()?);
            }
            "--new-ssh-key" => {
                only(&["rekey"])?;
                a.new_ssh_keys.push(value()?);
            }
            "--mode" => {
                only(&["encrypt"])?;
                a.opts.mode = Some(match value()?.as_str() {
                    "lines" => Mode::Lines,
                    "blob" => Mode::Blob,
                    "auto" => Mode::Auto,
                    _ => return Err(usage("--mode must be lines, blob or auto")),
                });
            }
            "--no-preserve-ws" => {
                only(&["encrypt"])?;
                a.opts.preserve_whitespace = Some(false);
            }
            "--pad" => {
                only(&["encrypt"])?;
                a.opts.pad = Some(int(value()?)?);
            }
            "--chunk" => {
                only(&["encrypt"])?;
                a.opts.chunk = Some(int(value()?)?);
            }
            "--seal" => {
                only(&["encrypt"])?;
                a.opts.seal = Some(true);
            }
            "--kdf" => {
                only(&["encrypt", "rekey"])?;
                a.kdf = Some(value()?);
            }
            "--previous" => {
                only(&["encrypt"])?;
                a.previous = Some(value()?);
            }
            "--fresh" => {
                only(&["encrypt"])?;
                a.fresh = true;
            }
            "--rewrap-only" => {
                only(&["rekey"])?;
                a.rewrap_only = true;
            }
            _ => return Err(usage(format!("unknown option '{opt}'"))),
        }
        i += 1;
    }
    if a.previous.is_some() && a.fresh {
        return Err(usage("--previous and --fresh exclude each other"));
    }
    Ok(a)
}

fn read_input(in_path: &Option<String>) -> Result<Vec<u8>, Failure> {
    let result = match in_path {
        Some(p) => std::fs::read(p),
        None => {
            let mut buf = Vec::new();
            std::io::stdin().lock().read_to_end(&mut buf).map(|_| buf)
        }
    };
    result.map_err(|e| plain_usage(format!("cannot read input: {e}")))
}

/// Called only once the whole result exists, so nothing is written on error.
fn write_output(out_path: &Option<String>, data: &[u8]) -> Result<(), Failure> {
    let result = match out_path {
        Some(p) => std::fs::write(p, data),
        None => {
            let mut out = std::io::stdout().lock();
            out.write_all(data).and_then(|_| out.flush())
        }
    };
    result.map_err(|e| plain_usage(format!("cannot write output: {e}")))
}

fn run(argv: &[String]) -> Result<(), Failure> {
    if argv.first().map(String::as_str) == Some("--version") {
        return write_output(&None, format!("ssenc {IMPL} {VERSION}\n").as_bytes());
    }
    if argv.is_empty() {
        return Err(usage("no command given"));
    }
    if argv[0] == "--help" || argv[0] == "-h" {
        return write_output(&None, format!("{USAGE}\n").as_bytes());
    }
    let cmd = argv[0].as_str();
    if !["encrypt", "decrypt", "rekey", "inspect"].contains(&cmd) {
        return Err(usage(format!("unknown command '{cmd}'")));
    }
    let mut args = parse_args(cmd, &argv[1..])?;

    if cmd == "inspect" {
        let info = inspect(&read_input(&args.in_path)?)?;
        return write_output(&None, format!("{}\n", info.to_json()).as_bytes());
    }

    // keys
    let mut password: Option<Vec<u8>> = None;
    if let Some(f) = &args.pw_file {
        password = Some(read_password_file(f)?);
    } else if let Some(p) = env_bytes("SSENC_PASSWORD") {
        password = Some(p);
    } else if args.ssh_keys.is_empty() {
        // Without -i the terminal is the data input, so it cannot also give the password.
        if !std::io::stdin().is_terminal() || args.in_path.is_none() {
            return Err(usage("no key given: use --password-file, SSENC_PASSWORD or --ssh-key"));
        }
        password = Some(prompt_password("ssenc password: ")?);
    }
    if password.as_ref().is_some_and(|p| p.is_empty()) {
        return Err(usage("password must not be empty"));
    }
    let mut keys: Vec<Key> = Vec::new();
    if cmd == "encrypt" {
        if let Some(p) = password {
            keys.push(Key::Password { password: p });
        }
        for k in &args.ssh_keys {
            keys.push(ssh_key_arg(k)?);
        }
    } else {
        if args.ssh_keys.len() > 1 {
            return Err(usage(format!("'{cmd}' takes a single --ssh-key")));
        }
        match (args.ssh_keys.first(), password) {
            (Some(k), _) => keys.push(ssh_key_arg(k)?),
            (None, Some(p)) => keys.push(Key::Password { password: p }),
            (None, None) => unreachable!("a password is always set when no ssh key is given"),
        }
    }

    match cmd {
        "encrypt" => {
            let mut opts = std::mem::take(&mut args.opts);
            opts.kdf = args.kdf.as_deref().map(Into::into);
            let mut auto_previous = false;
            if let Some(p) = &args.previous {
                opts.previous =
                    Some(std::fs::read(p).map_err(|e| plain_usage(format!("cannot read --previous file: {e}")))?);
            } else if let (false, Some(out)) = (args.fresh, &args.out_path) {
                if std::path::Path::new(out).exists() {
                    let existing = std::fs::read(out)
                        .map_err(|e| plain_usage(format!("cannot read existing output file {out}: {e}")))?;
                    if existing.starts_with(b"#ssenc1 ") {
                        opts.previous = Some(existing);
                        auto_previous = true;
                    }
                }
            }
            let input = read_input(&args.in_path)?;
            let out = encrypt(&input, &keys, &opts).map_err(|e| {
                if e.kind == ErrorKind::Auth && auto_previous {
                    Error::new(
                        ErrorKind::Auth,
                        "the existing output file cannot be opened with this key; use --fresh to overwrite it with a new data key",
                    )
                } else {
                    e
                }
            })?;
            write_output(&args.out_path, out.as_bytes())
        }
        "decrypt" => {
            let out = decrypt(&read_input(&args.in_path)?, &keys[0])?;
            write_output(&args.out_path, &out)
        }
        _ => {
            let mut new_keys: Vec<Key> = Vec::new();
            let new_password = match &args.new_pw_file {
                Some(f) => Some(read_password_file(f)?),
                None => env_bytes("SSENC_NEW_PASSWORD"),
            };
            if let Some(p) = new_password {
                if p.is_empty() {
                    return Err(usage("new password must not be empty"));
                }
                new_keys.push(Key::Password { password: p });
            }
            for k in &args.new_ssh_keys {
                new_keys.push(ssh_key_arg(k)?);
            }
            if new_keys.is_empty() {
                return Err(usage(
                    "no new key given: use --new-password-file, SSENC_NEW_PASSWORD or --new-ssh-key",
                ));
            }
            let opts = RekeyOptions {
                rotate_data_key: !args.rewrap_only,
                kdf: args.kdf.as_deref().map(Into::into),
            };
            let out = rekey(&read_input(&args.in_path)?, &keys[0], &new_keys, &opts)?;
            write_output(&args.out_path, out.as_bytes())
        }
    }
}

fn main() {
    let argv: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let code = match run(&argv) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("ssenc: {}: {}", e.kind, e.message);
            e.kind.exit_code()
        }
    };
    std::process::exit(code);
}
