use crate::error::AegisError;
use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6},
    process,
};

static HELP: &str = include_str!("../main.help.arg");
static ALLOW_HELP: &str = include_str!("../allow.help.arg");
static FORWARD_HELP: &str = include_str!("../forward.help.arg");
static PROXY_HELP: &str = include_str!("../proxy.help.arg");
static DENY_HELP: &str = include_str!("../deny.help.arg");
static IMPORT_HELP: &str = include_str!("../import.help.arg");
static BRIEF_LICENCE: &str = "This program is licensed under the Apache License, Version 2.0.";

#[derive(Debug)]
enum SubCommands {
    Forward,
    Proxy,
    Allow,
    Deny,
    Import,
}

#[derive(Debug)]
pub struct Args(pub ArgCommands);

#[derive(Debug)]
pub enum ArgCommands {
    Forward(ForwardArgs),
    Proxy(ProxyArgs),
    Allow(AllowArgs),
    Deny(DenyArgs),
    Import(String),
}
#[derive(Debug)]
pub struct ForwardArgs {
    pub v4: Option<(Ipv4Addr, u8, SocketAddrV4)>,
    pub v6: Option<(Ipv6Addr, u8, SocketAddrV6)>,
    pub port: Vec<u16>,
    pub directory: Option<String>,
    pub uid: Vec<u32>,
}
#[derive(Debug)]
pub struct ProxyArgs {
    pub v4: Option<(Ipv4Addr, u8, SocketAddrV4)>,
    pub v6: Option<(Ipv6Addr, u8, SocketAddrV6)>,
    pub port: Vec<u16>,
    pub directory: Option<String>,
    pub uid: Vec<u32>,
}
#[derive(Debug)]
pub struct AllowArgs {
    pub v4: Option<(Ipv4Addr, u8)>,
    pub v6: Option<(Ipv6Addr, u8)>,
    pub port: Vec<u16>,
    pub directory: Option<String>,
    pub uid: Vec<u32>,
}
#[derive(Debug)]
pub struct DenyArgs {
    pub v4: Option<(Ipv4Addr, u8)>,
    pub v6: Option<(Ipv6Addr, u8)>,
    pub port: Vec<u16>,
    pub directory: Option<String>,
    pub uid: Vec<u32>,
}

impl SubCommands {
    pub fn new(arg: &str) -> Result<Self, AegisError> {
        let mut types: HashMap<&str, usize> = HashMap::from([
            ("forward", 0),
            ("allow", 0),
            ("deny", 0),
            ("proxy", 0),
            ("import", 0),
        ]);
        for (i, c) in arg.chars().enumerate() {
            for (type_name, type_value) in types.iter_mut() {
                if *type_value == i && arg.len() <= type_name.len() {
                    if type_name.chars().nth(i) == Some(c) {
                        *type_value += 1;
                    } else {
                        *type_value = 0;
                    }
                }
            }
        }
        match types
            .iter()
            .filter(|(_, value)| **value != 0usize)
            .max_by(|(_, x_type_value), (_, y_type_value)| {
                x_type_value
                    .partial_cmp(y_type_value)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|(name, _)| *name)
            .ok_or(AegisError::CommandNotFound)?
        {
            "forward" => Ok(Self::Forward),
            "allow" => Ok(Self::Allow),
            "deny" => Ok(Self::Deny),
            "proxy" => Ok(Self::Proxy),
            "import" => Ok(Self::Import),
            _ => Err(AegisError::CommandNotFound),
        }
    }
}

impl Args {
    pub fn parse(
        raw: impl IntoIterator<Item = impl Into<std::ffi::OsString>>,
    ) -> Result<Self, AegisError> {
        let raw = clap_lex::RawArgs::new(raw);
        let mut cursor = raw.cursor();
        raw.next(&mut cursor);
        let command_arg = loop {
            let Some(arg) = raw.next(&mut cursor) else {
                print!("{}", HELP);
                process::exit(0x0);
            };
            if let Some((long, _value)) = arg.to_long() {
                match long {
                    Ok("help") => {
                        print!("{}", HELP);
                        process::exit(0x0);
                    }
                    Ok("version") => {
                        println!("tool, version {}", env!("CARGO_PKG_VERSION"));
                        println!("{}", BRIEF_LICENCE);
                        process::exit(0x0);
                    }
                    _ => {}
                }
            } else if let Some(mut shorts) = arg.to_short() {
                while let Some(short) = shorts.next_flag() {
                    if let Ok('h') = short {
                        print!("{}", HELP);
                        process::exit(0x0);
                    }
                }
                continue;
            }

            break arg;
        };
        match SubCommands::new(command_arg.to_value().or(Err(AegisError::Encoding))?)? {
            SubCommands::Import => {
                match raw
                    .next(&mut cursor)
                    .ok_or(AegisError::InvalidValue("Path required"))?
                    .to_value()
                {
                    Ok(path) if (["-h", "--help"].contains(&path)) => {
                        print!("{}", IMPORT_HELP);
                        process::exit(0x0);
                    }
                    Ok(path) => Ok(Self(ArgCommands::Import(path.to_string()))),
                    Err(_) => Err(AegisError::InvalidValue("Path required")),
                }
            }
            SubCommands::Proxy => {
                let mut sub = ProxyArgs {
                    v4: None,
                    v6: None,
                    port: Vec::new(),
                    directory: None,
                    uid: Vec::new(),
                };
                while let Some(arg) = raw.next(&mut cursor) {
                    if let Some((long, value)) = arg.to_long() {
                        match long {
                            Ok("ipv4") => {
                                sub.v4 = Some(
                                    value
                                        .and_then(|input| {
                                            input.to_str().and_then(|input| {
                                                Self::ipv4_prefix_dest_parse(input)
                                            })
                                        })
                                        .ok_or(AegisError::InvalidValue("ipv4"))?,
                                );
                            }
                            Ok("ipv6") => {
                                sub.v6 = Some(
                                    value
                                        .and_then(|input| {
                                            input.to_str().and_then(|input| {
                                                Self::ipv6_prefix_dest_parse(input)
                                            })
                                        })
                                        .ok_or(AegisError::InvalidValue("ipv6"))?,
                                );
                            }
                            Ok("port") => {
                                if let Some(port) =
                                    value.and_then(|input| input.to_str()).and_then(|input| {
                                        input
                                            .split(',')
                                            .map(|p| p.parse::<u16>().ok())
                                            .collect::<Option<Vec<u16>>>()
                                    })
                                {
                                    sub.port = port;
                                } else {
                                    return Err(AegisError::InvalidValue("port"));
                                }
                            }
                            Ok("uid") => {
                                if let Some(uid) =
                                    value.and_then(|input| input.to_str()).and_then(|input| {
                                        input
                                            .split(',')
                                            .map(|p| p.parse::<u32>().ok())
                                            .collect::<Option<Vec<u32>>>()
                                    })
                                {
                                    sub.uid = uid;
                                } else {
                                    return Err(AegisError::InvalidValue("uid"));
                                }
                            }
                            Ok("directory") => {
                                if let Some(path) = value.and_then(|input| input.to_str()) {
                                    sub.directory = Some(path.to_string());
                                } else {
                                    return Err(AegisError::InvalidValue("directory"));
                                }
                            }
                            Ok("help") => {
                                print!("{}", PROXY_HELP);
                                process::exit(0x0);
                            }
                            _ => {}
                        }
                    } else if let Some(mut shorts) = arg.to_short() {
                        while let Some(short) = shorts.next_flag() {
                            match short {
                                Ok('4') => {
                                    sub.v4 = Some(
                                        shorts
                                            .next_value_os()
                                            .or(raw.next_os(&mut cursor))
                                            .and_then(|input| input.to_str())
                                            .and_then(Self::ipv4_prefix_dest_parse)
                                            .ok_or(AegisError::InvalidValue("4"))?,
                                    );
                                }
                                Ok('6') => {
                                    sub.v6 = Some(
                                        shorts
                                            .next_value_os()
                                            .or(raw.next_os(&mut cursor))
                                            .and_then(|input| input.to_str())
                                            .and_then(Self::ipv6_prefix_dest_parse)
                                            .ok_or(AegisError::InvalidValue("6"))?,
                                    );
                                }
                                Ok('p') => {
                                    if let Some(port) = shorts
                                        .next_value_os()
                                        .or(raw.next_os(&mut cursor))
                                        .and_then(|input| input.to_str())
                                        .and_then(|input| {
                                            input
                                                .split(',')
                                                .map(|p| p.parse::<u16>().ok())
                                                .collect::<Option<Vec<u16>>>()
                                        })
                                    {
                                        sub.port = port;
                                    } else {
                                        return Err(AegisError::InvalidValue("p"));
                                    }
                                }
                                Ok('u') => {
                                    if let Some(uid) = shorts
                                        .next_value_os()
                                        .or(raw.next_os(&mut cursor))
                                        .and_then(|input| input.to_str())
                                        .and_then(|input| {
                                            input
                                                .split(',')
                                                .map(|p| p.parse::<u32>().ok())
                                                .collect::<Option<Vec<u32>>>()
                                        })
                                    {
                                        sub.uid = uid;
                                    } else {
                                        return Err(AegisError::InvalidValue("u"));
                                    }
                                }
                                Ok('d') => {
                                    if let Some(path) = shorts
                                        .next_value_os()
                                        .or(raw.next_os(&mut cursor))
                                        .and_then(|input| input.to_str())
                                    {
                                        sub.directory = Some(path.to_string());
                                    } else {
                                        return Err(AegisError::InvalidValue("d"));
                                    }
                                }
                                Ok('h') => {
                                    print!("{}", PROXY_HELP);
                                    process::exit(0x0);
                                }
                                _ => {}
                            }
                        }
                    }
                }
                if sub.v4.is_none() && sub.v6.is_none() {
                    return Err(AegisError::RequiredValue("ipv4 or ipv6 is required"));
                }
                Ok(Self(ArgCommands::Proxy(sub)))
            }
            SubCommands::Forward => {
                let mut sub = ForwardArgs {
                    v4: None,
                    v6: None,
                    port: Vec::new(),
                    directory: None,
                    uid: Vec::new(),
                };
                while let Some(arg) = raw.next(&mut cursor) {
                    if let Some((long, value)) = arg.to_long() {
                        match long {
                            Ok("ipv4") => {
                                sub.v4 = Some(
                                    value
                                        .and_then(|input| {
                                            input.to_str().and_then(|input| {
                                                Self::ipv4_prefix_dest_parse(input)
                                            })
                                        })
                                        .ok_or(AegisError::InvalidValue("ipv4"))?,
                                );
                            }
                            Ok("ipv6") => {
                                sub.v6 = Some(
                                    value
                                        .and_then(|input| {
                                            input.to_str().and_then(|input| {
                                                Self::ipv6_prefix_dest_parse(input)
                                            })
                                        })
                                        .ok_or(AegisError::InvalidValue("ipv6"))?,
                                );
                            }
                            Ok("port") => {
                                if let Some(port) =
                                    value.and_then(|input| input.to_str()).and_then(|input| {
                                        input
                                            .split(',')
                                            .map(|p| p.parse::<u16>().ok())
                                            .collect::<Option<Vec<u16>>>()
                                    })
                                {
                                    sub.port = port;
                                } else {
                                    return Err(AegisError::InvalidValue("port"));
                                }
                            }
                            Ok("uid") => {
                                if let Some(uid) =
                                    value.and_then(|input| input.to_str()).and_then(|input| {
                                        input
                                            .split(',')
                                            .map(|p| p.parse::<u32>().ok())
                                            .collect::<Option<Vec<u32>>>()
                                    })
                                {
                                    sub.uid = uid;
                                } else {
                                    return Err(AegisError::InvalidValue("uid"));
                                }
                            }
                            Ok("directory") => {
                                if let Some(path) = value.and_then(|input| input.to_str()) {
                                    sub.directory = Some(path.to_string());
                                } else {
                                    return Err(AegisError::InvalidValue("directory"));
                                }
                            }
                            Ok("help") => {
                                print!("{}", FORWARD_HELP);
                                process::exit(0x0);
                            }
                            _ => {}
                        }
                    } else if let Some(mut shorts) = arg.to_short() {
                        while let Some(short) = shorts.next_flag() {
                            match short {
                                Ok('4') => {
                                    sub.v4 = Some(
                                        shorts
                                            .next_value_os()
                                            .or(raw.next_os(&mut cursor))
                                            .and_then(|input| input.to_str())
                                            .and_then(Self::ipv4_prefix_dest_parse)
                                            .ok_or(AegisError::InvalidValue("4"))?,
                                    );
                                }
                                Ok('6') => {
                                    sub.v6 = Some(
                                        shorts
                                            .next_value_os()
                                            .or(raw.next_os(&mut cursor))
                                            .and_then(|input| input.to_str())
                                            .and_then(Self::ipv6_prefix_dest_parse)
                                            .ok_or(AegisError::InvalidValue("6"))?,
                                    );
                                }
                                Ok('p') => {
                                    if let Some(port) = shorts
                                        .next_value_os()
                                        .or(raw.next_os(&mut cursor))
                                        .and_then(|input| input.to_str())
                                        .and_then(|input| {
                                            input
                                                .split(',')
                                                .map(|p| p.parse::<u16>().ok())
                                                .collect::<Option<Vec<u16>>>()
                                        })
                                    {
                                        sub.port = port;
                                    } else {
                                        return Err(AegisError::InvalidValue("p"));
                                    }
                                }
                                Ok('u') => {
                                    if let Some(uid) = shorts
                                        .next_value_os()
                                        .or(raw.next_os(&mut cursor))
                                        .and_then(|input| input.to_str())
                                        .and_then(|input| {
                                            input
                                                .split(',')
                                                .map(|p| p.parse::<u32>().ok())
                                                .collect::<Option<Vec<u32>>>()
                                        })
                                    {
                                        sub.uid = uid;
                                    } else {
                                        return Err(AegisError::InvalidValue("u"));
                                    }
                                }
                                Ok('d') => {
                                    if let Some(path) = shorts
                                        .next_value_os()
                                        .or(raw.next_os(&mut cursor))
                                        .and_then(|input| input.to_str())
                                    {
                                        sub.directory = Some(path.to_string());
                                    } else {
                                        return Err(AegisError::InvalidValue("d"));
                                    }
                                }
                                Ok('h') => {
                                    print!("{}", FORWARD_HELP);
                                    process::exit(0x0);
                                }
                                _ => {}
                            }
                        }
                    }
                }
                if sub.v4.is_none() && sub.v6.is_none() {
                    return Err(AegisError::RequiredValue("ipv4 or ipv6 is required"));
                }
                Ok(Self(ArgCommands::Forward(sub)))
            }
            SubCommands::Allow => {
                let mut sub = AllowArgs {
                    v4: None,
                    v6: None,
                    port: Vec::new(),
                    directory: None,
                    uid: Vec::new(),
                };
                while let Some(arg) = raw.next(&mut cursor) {
                    if let Some((long, value)) = arg.to_long() {
                        match long {
                            Ok("ipv4") => {
                                sub.v4 = Some(
                                    value
                                        .and_then(|input| {
                                            input.to_str().and_then(Self::ipv4_prefix_parse)
                                        })
                                        .ok_or(AegisError::InvalidValue("ipv4"))?,
                                );
                            }
                            Ok("ipv6") => {
                                sub.v6 = Some(
                                    value
                                        .and_then(|input| {
                                            input.to_str().and_then(Self::ipv6_prefix_parse)
                                        })
                                        .ok_or(AegisError::InvalidValue("ipv6"))?,
                                );
                            }
                            Ok("port") => {
                                if let Some(port) =
                                    value.and_then(|input| input.to_str()).and_then(|input| {
                                        input
                                            .split(',')
                                            .map(|p| p.parse::<u16>().ok())
                                            .collect::<Option<Vec<u16>>>()
                                    })
                                {
                                    sub.port = port;
                                } else {
                                    return Err(AegisError::InvalidValue("port"));
                                }
                            }
                            Ok("uid") => {
                                if let Some(uid) =
                                    value.and_then(|input| input.to_str()).and_then(|input| {
                                        input
                                            .split(',')
                                            .map(|p| p.parse::<u32>().ok())
                                            .collect::<Option<Vec<u32>>>()
                                    })
                                {
                                    sub.uid = uid;
                                } else {
                                    return Err(AegisError::InvalidValue("uid"));
                                }
                            }
                            Ok("directory") => {
                                if let Some(path) = value.and_then(|input| input.to_str()) {
                                    sub.directory = Some(path.to_string());
                                } else {
                                    return Err(AegisError::InvalidValue("directory"));
                                }
                            }
                            Ok("help") => {
                                print!("{}", ALLOW_HELP);
                                process::exit(0x0);
                            }
                            _ => {}
                        }
                    } else if let Some(mut shorts) = arg.to_short() {
                        while let Some(short) = shorts.next_flag() {
                            match short {
                                Ok('4') => {
                                    sub.v4 = Some(
                                        shorts
                                            .next_value_os()
                                            .or(raw.next_os(&mut cursor))
                                            .and_then(|input| input.to_str())
                                            .and_then(Self::ipv4_prefix_parse)
                                            .ok_or(AegisError::InvalidValue("4"))?,
                                    );
                                }
                                Ok('6') => {
                                    sub.v6 = Some(
                                        shorts
                                            .next_value_os()
                                            .or(raw.next_os(&mut cursor))
                                            .and_then(|input| input.to_str())
                                            .and_then(Self::ipv6_prefix_parse)
                                            .ok_or(AegisError::InvalidValue("6"))?,
                                    );
                                }
                                Ok('p') => {
                                    if let Some(port) = shorts
                                        .next_value_os()
                                        .or(raw.next_os(&mut cursor))
                                        .and_then(|input| input.to_str())
                                        .and_then(|input| {
                                            input
                                                .split(',')
                                                .map(|p| p.parse::<u16>().ok())
                                                .collect::<Option<Vec<u16>>>()
                                        })
                                    {
                                        sub.port = port;
                                    } else {
                                        return Err(AegisError::InvalidValue("p"));
                                    }
                                }
                                Ok('u') => {
                                    if let Some(uid) = shorts
                                        .next_value_os()
                                        .or(raw.next_os(&mut cursor))
                                        .and_then(|input| input.to_str())
                                        .and_then(|input| {
                                            input
                                                .split(',')
                                                .map(|p| p.parse::<u32>().ok())
                                                .collect::<Option<Vec<u32>>>()
                                        })
                                    {
                                        sub.uid = uid;
                                    } else {
                                        return Err(AegisError::InvalidValue("u"));
                                    }
                                }
                                Ok('d') => {
                                    if let Some(path) = shorts
                                        .next_value_os()
                                        .or(raw.next_os(&mut cursor))
                                        .and_then(|input| input.to_str())
                                    {
                                        sub.directory = Some(path.to_string());
                                    } else {
                                        return Err(AegisError::InvalidValue("d"));
                                    }
                                }
                                Ok('h') => {
                                    print!("{}", ALLOW_HELP);
                                    process::exit(0x0);
                                }
                                _ => {}
                            }
                        }
                    }
                }
                if sub.v4.is_none() && sub.v6.is_none() {
                    sub.v4 = Some((Ipv4Addr::UNSPECIFIED, 0));
                    sub.v6 = Some((Ipv6Addr::UNSPECIFIED, 0));
                }
                Ok(Self(ArgCommands::Allow(sub)))
            }
            SubCommands::Deny => {
                let mut sub = DenyArgs {
                    v4: None,
                    v6: None,
                    port: Vec::new(),
                    directory: None,
                    uid: Vec::new(),
                };
                while let Some(arg) = raw.next(&mut cursor) {
                    if let Some((long, value)) = arg.to_long() {
                        match long {
                            Ok("ipv4") => {
                                sub.v4 = Some(
                                    value
                                        .and_then(|input| {
                                            input.to_str().and_then(Self::ipv4_prefix_parse)
                                        })
                                        .ok_or(AegisError::InvalidValue("ipv4"))?,
                                );
                            }
                            Ok("ipv6") => {
                                sub.v6 = Some(
                                    value
                                        .and_then(|input| {
                                            input.to_str().and_then(Self::ipv6_prefix_parse)
                                        })
                                        .ok_or(AegisError::InvalidValue("ipv6"))?,
                                );
                            }
                            Ok("port") => {
                                if let Some(port) =
                                    value.and_then(|input| input.to_str()).and_then(|input| {
                                        input
                                            .split(',')
                                            .map(|p| p.parse::<u16>().ok())
                                            .collect::<Option<Vec<u16>>>()
                                    })
                                {
                                    sub.port = port;
                                } else {
                                    return Err(AegisError::InvalidValue("port"));
                                }
                            }
                            Ok("uid") => {
                                if let Some(uid) =
                                    value.and_then(|input| input.to_str()).and_then(|input| {
                                        input
                                            .split(',')
                                            .map(|p| p.parse::<u32>().ok())
                                            .collect::<Option<Vec<u32>>>()
                                    })
                                {
                                    sub.uid = uid;
                                } else {
                                    return Err(AegisError::InvalidValue("uid"));
                                }
                            }
                            Ok("directory") => {
                                if let Some(path) = value.and_then(|input| input.to_str()) {
                                    sub.directory = Some(path.to_string());
                                } else {
                                    return Err(AegisError::InvalidValue("directory"));
                                }
                            }
                            Ok("help") => {
                                print!("{}", DENY_HELP);
                                process::exit(0x0);
                            }
                            _ => {}
                        }
                    } else if let Some(mut shorts) = arg.to_short() {
                        while let Some(short) = shorts.next_flag() {
                            match short {
                                Ok('4') => {
                                    sub.v4 = Some(
                                        shorts
                                            .next_value_os()
                                            .or(raw.next_os(&mut cursor))
                                            .and_then(|input| input.to_str())
                                            .and_then(Self::ipv4_prefix_parse)
                                            .ok_or(AegisError::InvalidValue("4"))?,
                                    );
                                }
                                Ok('6') => {
                                    sub.v6 = Some(
                                        shorts
                                            .next_value_os()
                                            .or(raw.next_os(&mut cursor))
                                            .and_then(|input| input.to_str())
                                            .and_then(Self::ipv6_prefix_parse)
                                            .ok_or(AegisError::InvalidValue("6"))?,
                                    );
                                }
                                Ok('p') => {
                                    if let Some(port) = shorts
                                        .next_value_os()
                                        .or(raw.next_os(&mut cursor))
                                        .and_then(|input| input.to_str())
                                        .and_then(|input| {
                                            input
                                                .split(',')
                                                .map(|p| p.parse::<u16>().ok())
                                                .collect::<Option<Vec<u16>>>()
                                        })
                                    {
                                        sub.port = port;
                                    } else {
                                        return Err(AegisError::InvalidValue("p"));
                                    }
                                }
                                Ok('u') => {
                                    if let Some(uid) = shorts
                                        .next_value_os()
                                        .or(raw.next_os(&mut cursor))
                                        .and_then(|input| input.to_str())
                                        .and_then(|input| {
                                            input
                                                .split(',')
                                                .map(|p| p.parse::<u32>().ok())
                                                .collect::<Option<Vec<u32>>>()
                                        })
                                    {
                                        sub.uid = uid;
                                    } else {
                                        return Err(AegisError::InvalidValue("u"));
                                    }
                                }
                                Ok('d') => {
                                    if let Some(path) = shorts
                                        .next_value_os()
                                        .or(raw.next_os(&mut cursor))
                                        .and_then(|input| input.to_str())
                                    {
                                        sub.directory = Some(path.to_string());
                                    } else {
                                        return Err(AegisError::InvalidValue("d"));
                                    }
                                }
                                Ok('h') => {
                                    print!("{}", DENY_HELP);
                                    process::exit(0x0);
                                }
                                _ => return Err(AegisError::CommandNotFound),
                            }
                        }
                    }
                }
                if sub.v4.is_none() && sub.v6.is_none() {
                    sub.v4 = Some((Ipv4Addr::UNSPECIFIED, 0));
                    sub.v6 = Some((Ipv6Addr::UNSPECIFIED, 0));
                }
                Ok(Self(ArgCommands::Deny(sub)))
            }
        }
    }
    // pub fn take_conf_path(&mut self) -> Option<String> {
    //     self.config_path.take()
    // }
    fn ipv4_prefix_parse(input: &str) -> Option<(Ipv4Addr, u8)> {
        input
            .split_once("/")
            .and_then(|(ip, prefix)| {
                prefix
                    .parse::<u8>()
                    .ok()
                    .and_then(|p| ip.parse::<Ipv4Addr>().ok().map(|a| (a, p)))
            })
            .or(input.parse::<Ipv4Addr>().ok().map(|a| (a, 32)))
            .filter(|(_, mask)| mask <= &32)
    }
    fn ipv6_prefix_parse(input: &str) -> Option<(Ipv6Addr, u8)> {
        input
            .split_once("/")
            .and_then(|(ip, prefix)| {
                prefix
                    .parse::<u8>()
                    .ok()
                    .and_then(|p| ip.parse::<Ipv6Addr>().ok().map(|a| (a, p)))
            })
            .or(input.parse::<Ipv6Addr>().ok().map(|a| (a, 128)))
            .filter(|(_, mask)| mask <= &128)
    }
    fn ipv4_prefix_dest_parse(input: &str) -> Option<(Ipv4Addr, u8, SocketAddrV4)> {
        input.split_once("=").and_then(|(ip, dest)| {
            Self::ipv4_prefix_parse(ip).and_then(|(ipv4, prefix)| {
                dest.parse::<SocketAddrV4>()
                    .ok()
                    .or(dest
                        .parse::<Ipv4Addr>()
                        .ok()
                        .map(|a| SocketAddrV4::new(a, 0)))
                    .map(|dest| (ipv4, prefix, dest))
            })
        })
    }
    fn ipv6_prefix_dest_parse(input: &str) -> Option<(Ipv6Addr, u8, SocketAddrV6)> {
        input.split_once("=").and_then(|(ip, dest)| {
            Self::ipv6_prefix_parse(ip).and_then(|(ipv4, prefix)| {
                dest.parse::<SocketAddrV6>()
                    .ok()
                    .or(dest
                        .parse::<Ipv6Addr>()
                        .ok()
                        .map(|a| SocketAddrV6::new(a, 0, 0, 0)))
                    .map(|dest| (ipv4, prefix, dest))
            })
        })
    }
}
