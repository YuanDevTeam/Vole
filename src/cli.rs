//! CLI adapter: arguments -> Invoke request -> output and exit status.
use serde_json::{Value, json};
use std::{
    ffi::{OsStr, OsString},
    io::{self, Write},
    path::PathBuf,
    process::ExitCode,
};
use vole::invoke::{InvokePath, invoke_owned_bytes};
use zeroize::{Zeroize, Zeroizing};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Help,
    Version,
    Validate,
    Run,
}

#[derive(PartialEq, Eq)]
struct Options {
    mode: Mode,
    data_dir: Option<PathBuf>,
    config_file: Option<PathBuf>,
    config_string: Option<Zeroizing<String>>,
    age_secret_key: Option<Zeroizing<String>>,
    external_controller: Option<Zeroizing<String>>,
    external_controller_tls: Option<Zeroizing<String>>,
    external_controller_unix: Option<Zeroizing<String>>,
    external_controller_routing_mark: Option<i64>,
    secret: Option<Zeroizing<String>>,
    http_config_file: Option<PathBuf>,
    http_ca_file: Option<PathBuf>,
}

impl std::fmt::Debug for Options {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Options")
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

impl Options {
    fn parse(
        arguments: impl IntoIterator<Item = OsString>,
        data_dir: Option<OsString>,
        config_file: Option<OsString>,
    ) -> Result<Self, CliError> {
        let mut arguments = arguments.into_iter();
        let (mut version, mut validate) = (false, false);
        let mut data_dir = data_dir.map(PathBuf::from);
        let mut config_file = config_file.map(PathBuf::from);
        let mut config_string = None;
        let mut age_secret_key = None;
        let mut external_controller = None;
        let mut external_controller_tls = None;
        let mut external_controller_unix = None;
        let mut external_controller_routing_mark = None;
        let mut secret = None;
        let mut http_config_file = None;
        let mut http_ca_file = None;
        while let Some(argument) = arguments.next() {
            let Some((flag, inline)) = flag_parts(&argument)? else {
                // Like Go flag, a positional argument or -- ends parsing.
                // The CLI defines no positional commands, so the remainder
                // supplies no business configuration or additional options.
                break;
            };
            match flag {
                b"h" | b"help" => {
                    return Ok(Self {
                        mode: Mode::Help,
                        data_dir,
                        config_file,
                        config_string,
                        age_secret_key,
                        external_controller,
                        external_controller_tls,
                        external_controller_unix,
                        external_controller_routing_mark,
                        secret,
                        http_config_file,
                        http_ca_file,
                    });
                }
                b"v" | b"t" => {
                    let value = inline.map_or(Ok(true), parse_bool)?;
                    if flag == b"v" {
                        version = value;
                    } else {
                        validate = value;
                    }
                }
                b"ext-ctl-routing-mark" => {
                    let value = inline
                        .map(OsStr::to_owned)
                        .or_else(|| arguments.next())
                        .ok_or(CliError::argument(
                            "missing value for -ext-ctl-routing-mark",
                        ))?;
                    external_controller_routing_mark = Some(parse_go_int(&value)?);
                }
                b"config" | b"age-secret-key" | b"ext-ctl" | b"ext-ctl-tls" | b"ext-ctl-unix"
                | b"secret" => {
                    let value = inline
                        .map(OsStr::to_owned)
                        .or_else(|| arguments.next())
                        .ok_or(CliError::argument(match flag {
                            b"config" => "missing value for -config",
                            b"age-secret-key" => "missing value for -age-secret-key",
                            b"ext-ctl" => "missing value for -ext-ctl",
                            b"ext-ctl-tls" => "missing value for -ext-ctl-tls",
                            b"ext-ctl-unix" => "missing value for -ext-ctl-unix",
                            _ => "missing value for -secret",
                        }))?;
                    let value = value.into_string().map(Zeroizing::new).map_err(|value| {
                        drop(Zeroizing::new(value.into_encoded_bytes()));
                        CliError::argument("text option requires UTF-8")
                    })?;
                    match flag {
                        b"config" => config_string = Some(value),
                        b"age-secret-key" => age_secret_key = Some(value),
                        b"ext-ctl" => external_controller = Some(value),
                        b"ext-ctl-tls" => external_controller_tls = Some(value),
                        b"ext-ctl-unix" => external_controller_unix = Some(value),
                        _ => secret = Some(value),
                    }
                    drop(Zeroizing::new(argument.into_encoded_bytes()));
                }
                b"http-config" | b"http-ca" => {
                    let value = inline
                        .map(OsStr::to_owned)
                        .or_else(|| arguments.next())
                        .ok_or(CliError::argument(if flag == b"http-ca" {
                            "missing value for -http-ca"
                        } else {
                            "missing value for -http-config"
                        }))?;
                    if flag == b"http-ca" {
                        http_ca_file = Some(PathBuf::from(value));
                    } else {
                        http_config_file = Some(PathBuf::from(value));
                    }
                }
                b"d" | b"f" => {
                    let value = inline
                        .map(OsStr::to_owned)
                        .or_else(|| arguments.next())
                        .ok_or(CliError::argument(if flag == b"d" {
                            "missing value for -d"
                        } else {
                            "missing value for -f"
                        }))?;
                    if flag == b"d" {
                        data_dir = Some(PathBuf::from(value));
                    } else {
                        config_file = Some(PathBuf::from(value));
                    }
                }
                _ => return Err(CliError::argument("unknown option")),
            }
        }
        Ok(Self {
            mode: if version {
                Mode::Version
            } else if validate {
                Mode::Validate
            } else {
                Mode::Run
            },
            data_dir,
            config_file,
            config_string,
            age_secret_key,
            external_controller,
            external_controller_tls,
            external_controller_unix,
            external_controller_routing_mark,
            secret,
            http_config_file,
            http_ca_file,
        })
    }
}

type ParsedFlag<'a> = (&'a [u8], Option<&'a OsStr>);

fn flag_parts(argument: &OsStr) -> Result<Option<ParsedFlag<'_>>, CliError> {
    let encoded = argument.as_encoded_bytes();
    if encoded.len() < 2 || encoded[0] != b'-' || encoded == b"--" {
        return Ok(None);
    }
    let offset = if encoded[1] == b'-' { 2 } else { 1 };
    let flag = &encoded[offset..];
    if flag.is_empty() || matches!(flag[0], b'-' | b'=') {
        return Err(CliError::argument("invalid option syntax"));
    }
    if let Some(equals) = flag.iter().position(|byte| *byte == b'=') {
        // '=' is a complete ASCII/UTF-8 character. Splitting this original
        // OsStr immediately after it preserves the platform encoded suffix,
        // including non-Unicode Unix bytes and Windows native characters.
        let value = unsafe { OsStr::from_encoded_bytes_unchecked(&flag[equals + 1..]) };
        Ok(Some((&flag[..equals], Some(value))))
    } else {
        Ok(Some((flag, None)))
    }
}

// Go flag.IntVar uses strconv.ParseInt(base=0, bitSize=strconv.IntSize).
fn parse_go_int(value: &OsStr) -> Result<i64, CliError> {
    let invalid = || CliError::argument("invalid integer option value");
    let mut digits = value.as_encoded_bytes();
    let negative = digits.first() == Some(&b'-');
    if matches!(digits.first(), Some(b'+' | b'-')) {
        digits = &digits[1..];
    }
    if digits.is_empty() {
        return Err(invalid());
    }
    let mut radix = 10_u64;
    let mut prefix = false;
    if digits.len() > 1 && digits[0] == b'0' {
        prefix = true;
        let offset = match digits[1] {
            b'x' | b'X' => {
                radix = 16;
                2
            }
            b'b' | b'B' => {
                radix = 2;
                2
            }
            b'o' | b'O' => {
                radix = 8;
                2
            }
            _ => {
                radix = 8;
                1
            }
        };
        digits = &digits[offset..];
    }
    let decode = |byte: u8| {
        match byte {
            b'0'..=b'9' => Some(u64::from(byte - b'0')),
            b'a'..=b'f' => Some(u64::from(byte - b'a' + 10)),
            b'A'..=b'F' => Some(u64::from(byte - b'A' + 10)),
            _ => None,
        }
        .filter(|digit| *digit < radix)
    };
    let limit = (isize::MAX as u64) + u64::from(negative);
    let mut value = 0_u64;
    let mut previous_digit = false;
    let mut any_digit = false;
    for (index, &byte) in digits.iter().enumerate() {
        if byte == b'_' {
            if !(previous_digit || index == 0 && prefix)
                || digits
                    .get(index + 1)
                    .and_then(|next| decode(*next))
                    .is_none()
            {
                return Err(invalid());
            }
            previous_digit = false;
        } else {
            let digit = decode(byte).ok_or_else(invalid)?;
            value = value
                .checked_mul(radix)
                .and_then(|value| value.checked_add(digit))
                .filter(|value| *value <= limit)
                .ok_or_else(invalid)?;
            previous_digit = true;
            any_digit = true;
        }
    }
    if !any_digit {
        return Err(invalid());
    }
    let signed = if negative {
        -(value as i128)
    } else {
        value as i128
    };
    Ok(signed as i64)
}

fn parse_bool(value: &OsStr) -> Result<bool, CliError> {
    match value.as_encoded_bytes() {
        b"1" | b"t" | b"T" | b"TRUE" | b"true" | b"True" => Ok(true),
        b"0" | b"f" | b"F" | b"FALSE" | b"false" | b"False" => Ok(false),
        _ => Err(CliError::argument("invalid boolean option value")),
    }
}

#[derive(Debug)]
struct CliError(&'static str);
impl CliError {
    fn argument(message: &'static str) -> Self {
        Self(message)
    }
}
fn request(options: Options) -> Value {
    if options.mode == Mode::Help {
        return json!({"method":"foreground","payload":{"action":"help"}});
    }
    if options.mode == Mode::Version {
        return json!({"method":"version","payload":{}});
    }
    let mut payload = json!({"action":match options.mode {Mode::Help=>"help",Mode::Validate=>"validate",_=>"run"}});
    if let Some(path) = options.data_dir {
        payload["dataDir"] =
            serde_json::to_value(InvokePath::from(path)).expect("native path serialization");
    }
    if let Some(path) = options.config_file {
        payload["configPath"] =
            serde_json::to_value(InvokePath::from(path)).expect("native path serialization");
    }
    for (name, value) in [
        ("configString", options.config_string),
        ("ageSecretKey", options.age_secret_key),
        ("externalController", options.external_controller),
        ("externalControllerTls", options.external_controller_tls),
        ("externalControllerUnix", options.external_controller_unix),
        ("secret", options.secret),
    ] {
        if let Some(mut value) = value {
            payload[name] = Value::String(std::mem::take(&mut *value));
        }
    }
    if let Some(mark) = options.external_controller_routing_mark {
        payload["externalControllerRoutingMark"] = Value::from(mark);
    }
    if let Some(path) = options.http_config_file {
        payload["httpConfigPath"] =
            serde_json::to_value(InvokePath::from(path)).expect("native path serialization");
    }
    if let Some(path) = options.http_ca_file {
        payload["httpCaPath"] =
            serde_json::to_value(InvokePath::from(path)).expect("native path serialization");
    }
    let mut request = json!({"method":"foreground"});
    request["payload"] = payload;
    request
}
fn call(mut request: Value) -> Result<Value, CliError> {
    let bytes = serde_json::to_vec(&request);
    for name in ["configString", "ageSecretKey", "secret"] {
        if let Some(Value::String(value)) = request["payload"].get_mut(name) {
            value.zeroize();
        }
    }
    drop(request);
    let bytes = bytes.map_err(|_| CliError("request serialization failed"))?;
    serde_json::from_slice(&invoke_owned_bytes(bytes))
        .map_err(|_| CliError("invalid Invoke response"))
}
fn render(
    response: &Value,
    output: &mut impl Write,
    diagnostics: &mut impl Write,
) -> io::Result<u8> {
    if response["success"] != true {
        writeln!(
            diagnostics,
            "vole: {}",
            response["error"].as_str().unwrap_or("Invoke failed")
        )?;
        return Ok(1);
    }
    let data = &response["data"];
    if let (Some(version), Some(identity)) =
        (data["version"].as_str(), data["buildIdentity"].as_str())
    {
        writeln!(output, "Vole {version}\n{identity}")?;
    } else {
        output.write_all(data["output"].as_str().unwrap_or("").as_bytes())?;
        diagnostics.write_all(data["diagnostics"].as_str().unwrap_or("").as_bytes())?;
    }
    Ok(0)
}
pub(crate) fn entry() -> ExitCode {
    let mut output = io::stdout();
    let mut diagnostics = io::stderr();
    let options = match Options::parse(std::env::args_os().skip(1), None, None) {
        Ok(options) => options,
        Err(error) => {
            let _ = writeln!(diagnostics, "vole: {}", error.0);
            if let Ok(help) = call(json!({"method":"foreground","payload":{"action":"help"}})) {
                let _ = render(&help, &mut output, &mut diagnostics);
            }
            return ExitCode::from(2);
        }
    };
    match call(request(options)) {
        Ok(response) => {
            ExitCode::from(render(&response, &mut output, &mut diagnostics).unwrap_or(1))
        }
        Err(error) => {
            let _ = writeln!(diagnostics, "vole: {}", error.0);
            ExitCode::from(1)
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn parse(args: &[&str]) -> Result<Options, CliError> {
        Options::parse(args.iter().map(OsString::from), None, None)
    }
    #[test]
    fn controller_mark_flag_uses_go_integer_syntax_and_numeric_invoke_metadata() {
        for (input, expected) in [
            ("42", 42),
            ("0x2a", 42),
            ("0o52", 42),
            ("0b10_1010", 42),
            ("052", 42),
            ("0x_2a", 42),
            ("-1", -1),
            ("+0", 0),
        ] {
            let options = Options::parse(
                ["-t".into(), format!("-ext-ctl-routing-mark={input}").into()],
                None,
                None,
            )
            .unwrap();
            assert_eq!(
                request(options)["payload"]["externalControllerRoutingMark"],
                expected
            );
        }
        for invalid in ["08", "1__2", "0x", "9223372036854775808"] {
            assert!(
                Options::parse(
                    [
                        "-t".into(),
                        format!("-ext-ctl-routing-mark={invalid}").into()
                    ],
                    None,
                    None
                )
                .is_err()
            );
        }
    }
    #[test]
    fn unix_controller_flag_only_transports_the_explicit_text_value() {
        let options = Options::parse(["-ext-ctl-unix=/run/vole.sock".into()], None, None).unwrap();
        let value = request(options);
        assert_eq!(value["payload"]["externalControllerUnix"], "/run/vole.sock");
        assert!(Options::parse(["-ext-ctl-unix".into()], None, None).is_err());
    }

    #[test]
    fn supported_go_flag_spellings_and_priority() {
        for value in ["true", "T", "TRUE", "1", "t", "True"] {
            assert_eq!(
                parse(&[&format!("--t={value}")]).unwrap().mode,
                Mode::Validate
            );
        }
        for value in ["false", "F", "FALSE", "0", "f", "False"] {
            assert_eq!(parse(&[&format!("-t={value}")]).unwrap().mode, Mode::Run);
        }
        assert_eq!(parse(&["-t", "-v"]).unwrap().mode, Mode::Version);
        assert_eq!(
            parse(&["-v", "--v=false", "-t"]).unwrap().mode,
            Mode::Validate
        );
        assert_eq!(parse(&["-h", "-unknown"]).unwrap().mode, Mode::Help);
        assert!(parse(&["-unknown", "-h"]).is_err());
        assert_eq!(parse(&["positional", "-v"]).unwrap().mode, Mode::Run);
        assert_eq!(parse(&["--", "-v"]).unwrap().mode, Mode::Run);
    }
    #[test]
    fn requests_preserve_raw_options_and_empty_reset() {
        let req = request(parse(&["--d=relative-data", "-f", "-", "-t"]).unwrap());
        assert_eq!(
            req,
            json!({"method":"foreground","payload":{"action":"validate","dataDir":"relative-data","configPath":"-"}})
        );
        assert_eq!(
            request(parse(&["-d=", "-f="]).unwrap())["payload"]["dataDir"],
            ""
        );
        assert_eq!(
            request(parse(&["-v", "-f", "missing"]).unwrap()),
            json!({"method":"version","payload":{}})
        );
        assert!(
            request(parse(&[]).unwrap())["payload"]
                .get("dataDir")
                .is_none()
        );
    }
    #[test]
    fn invalid_flags_are_redacted() {
        for args in [
            vec!["-password=secret"],
            vec!["-t=secret"],
            vec!["-f"],
            vec!["---f"],
        ] {
            let error = parse(&args).unwrap_err();
            assert!(!error.0.contains("secret"));
        }
    }
    #[cfg(unix)]
    #[test]
    fn native_paths_are_transmitted_losslessly() {
        use std::os::unix::ffi::OsStringExt;
        let mut raw = b"-f=".to_vec();
        raw.push(255);
        let options = Options::parse([OsString::from_vec(raw)], None, None).unwrap();
        assert_eq!(
            request(options)["payload"]["configPath"],
            json!({"unixBytes":[255]})
        );
    }
    #[test]
    fn encoded_configuration_and_age_options_only_transport_text() {
        let options = parse(&[
            "-config",
            "c2VjcmV0",
            "--age-secret-key=private-fixture",
            "-t",
        ])
        .unwrap();
        assert!(!format!("{options:?}").contains("private-fixture"));
        assert!(!format!("{options:?}").contains("c2VjcmV0"));
        let value = request(options);
        assert_eq!(value["payload"]["configString"], "c2VjcmV0");
        assert_eq!(value["payload"]["ageSecretKey"], "private-fixture");
        assert_eq!(
            request(parse(&["-config=", "-t"]).unwrap())["payload"]["configString"],
            ""
        );
        assert_eq!(
            request(parse(&["-config=invalid", "-v"]).unwrap()),
            json!({"method":"version","payload":{}})
        );
    }
    #[test]
    fn controller_override_options_only_transport_specific_values() {
        let options = parse(&[
            "-ext-ctl=:9900",
            "--ext-ctl-tls",
            "localhost:9943",
            "-secret",
            "private-token",
            "-t",
        ])
        .unwrap();
        assert!(!format!("{options:?}").contains("private-token"));
        let value = request(options);
        assert_eq!(value["payload"]["externalController"], ":9900");
        assert_eq!(value["payload"]["externalControllerTls"], "localhost:9943");
        assert_eq!(value["payload"]["secret"], "private-token");
        assert_eq!(
            request(parse(&["-secret=", "-t"]).unwrap())["payload"]["secret"],
            ""
        );
    }
    #[test]
    fn result_streams_and_failure_status() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        assert_eq!(
            render(
                &json!({"success":true,"data":{"output":"ok","diagnostics":"help"}}),
                &mut out,
                &mut err
            )
            .unwrap(),
            0
        );
        assert_eq!(out, b"ok");
        assert_eq!(err, b"help");
        assert_eq!(
            render(
                &json!({"success":false,"error":"failed"}),
                &mut out,
                &mut err
            )
            .unwrap(),
            1
        );
    }

    #[test]
    fn http_addendum_option_only_transports_an_explicit_native_path() {
        for option in ["-http-config=extra.yaml", "--http-config=extra.yaml"] {
            let value = request(parse(&[option, "-t"]).unwrap());
            assert_eq!(value["payload"]["httpConfigPath"], "extra.yaml");
        }
        let value = request(
            parse(&[
                "-http-config",
                "extra.yaml",
                "-http-ca",
                "private.json",
                "-t",
            ])
            .unwrap(),
        );
        assert_eq!(value["payload"]["httpCaPath"], "private.json");
        assert_eq!(
            request(parse(&["-http-config", "extra.yaml", "-v"]).unwrap()),
            json!({"method":"version","payload":{}})
        );
    }
}
