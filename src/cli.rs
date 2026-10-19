//! CLI adapter: arguments -> Invoke request -> output and exit status.
use serde_json::{Value, json};
use std::{
    ffi::{OsStr, OsString},
    io::{self, Write},
    path::PathBuf,
    process::ExitCode,
};
use vole::invoke::{InvokePath, invoke_bytes};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Help,
    Version,
    Validate,
    Run,
}

#[derive(Debug, PartialEq, Eq)]
struct Options {
    mode: Mode,
    data_dir: Option<PathBuf>,
    config_file: Option<PathBuf>,
    http_config_file: Option<PathBuf>,
    http_ca_file: Option<PathBuf>,
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
    if let Some(path) = options.http_config_file {
        payload["httpConfigPath"] =
            serde_json::to_value(InvokePath::from(path)).expect("native path serialization");
    }
    if let Some(path) = options.http_ca_file {
        payload["httpCaPath"] =
            serde_json::to_value(InvokePath::from(path)).expect("native path serialization");
    }
    json!({"method":"foreground","payload":payload})
}
fn call(request: Value) -> Result<Value, CliError> {
    let bytes =
        serde_json::to_vec(&request).map_err(|_| CliError("request serialization failed"))?;
    serde_json::from_slice(&invoke_bytes(&bytes)).map_err(|_| CliError("invalid Invoke response"))
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
