use crate::error::AegisError;
use std::{collections::HashMap, net::SocketAddr, process};

static HELP: &str = include_str!("../main.help.arg");
static ALLOW_HELP: &str = include_str!("../allow.help.arg");
static FORWARD_HELP: &str = include_str!("../forward.help.arg");
static PROXY_HELP: &str = include_str!("../proxy.help.arg");
static DENY_HELP: &str = include_str!("../deny.help.arg");
static BRIEF_LICENCE: &str = "This program is licensed under the Apache License, Version 2.0.";

#[derive(Debug)]
enum SubCommands {
    Forward,
    Proxy,
    Allow,
    Deny,
}

pub struct Args(ArgCommands);

#[derive(Debug)]
pub enum ArgCommands {
    Forward(()),
    List(()),
    Allow(()),
    Deny(()),
}


impl SubCommands {
    pub fn new(arg: &str) -> Result<Self, AegisError> {
        let mut types: HashMap<&str, usize> = HashMap::from([
            ("forward", 0),
            ("allow", 0),
            ("deny", 0),
            ("proxy", 0),
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
        let mut config_path = None;
        let command_arg = loop {
            let Some(arg) = raw.next(&mut cursor) else {
                print!("{}", HELP);
                process::exit(0x0);
            };
            if let Some((long, value)) = arg.to_long() {
                match long {
                    Ok("config") => {
                        config_path = Some(
                            value
                                .ok_or(AegisError::RequiredValue("config"))?
                                .to_str()
                                .ok_or(AegisError::Encoding)?
                                .to_owned(),
                        );
                        continue;
                    }
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
                    match short {
                        Ok('c') => {
                            config_path = if let Some(v) = shorts.next_value_os() {
                                v.to_str().map(|s| s.to_string())
                            } else if let Some(v) = raw.next_os(&mut cursor) {
                                v.to_str()
                                    .filter(|v| !v.is_empty() && v.find('-') != Some(0))
                                    .map(|v| v.to_string())
                            } else {
                                return Err(AegisError::RequiredValue("config"));
                            };
                        }
                        Ok('h') => {
                            print!("{}", HELP);
                            process::exit(0x0);
                        }
                        _ => {}
                    }
                }
                continue;
            }

            break arg;
        };
        return Err(AegisError::Encoding);

    }
    // pub fn take_conf_path(&mut self) -> Option<String> {
    //     self.config_path.take()
    // }
}

