use std::env;
use std::process::Command;

use anyhow::{bail, ensure, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug)]
struct Query {
    node: u16,
    key: String,
}

#[derive(Serialize)]
struct Response {
    status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    server: Option<WireGuardInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client: Option<WireGuardInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct WireGuardInfo {
    node: u16,
    key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
}

#[derive(Serialize)]
enum Status {
    NotConfigured,
    NotRestricted,
    Restricted,
    RequestAccepted,
    RequestAlreadyRegistered,
    RequestFailed,
}

fn uci_get(key: &str) -> Result<String> {
    let output = Command::new("uci").arg("get").arg("-q").arg(key).output()?;
    Ok(String::from_utf8(output.stdout)
        .unwrap_or_default()
        .replace('\n', ""))
}

fn get_server_status() -> Result<(WireGuardInfo, bool, String)> {
    let uci_public = &uci_get("wg_cgi.uci.wg_public_key")?;
    let uci_node = &uci_get("wg_cgi.uci.node_id")?;
    let uci_restrict = &uci_get("wg_cgi.uci.wg_restrict")?;
    let uci_port = &uci_get("wg_cgi.uci.wg_ext_port")?;
    let wg_backbone_path = uci_get("wg_cgi.sh.wg_backbone_path").unwrap_or_default();

    let key = uci_get(uci_public)?;
    let node = uci_get(uci_node)?.parse::<u16>()?;
    let server_restricted = uci_get(uci_restrict)?.trim() == "1";
    let server_port = uci_get(uci_port)
        .unwrap_or_else(|_| "5003".to_string())
        .parse::<u16>()
        .unwrap_or(5003);

    Ok((
        WireGuardInfo {
            node,
            key,
            port: Some(server_port),
        },
        server_restricted,
        wg_backbone_path,
    ))
}

fn register_wg(wg_backbone_path: &str, query_string: &str) -> Result<(WireGuardInfo, bool)> {
    let key_check = Regex::new("[0-9a-zA-Z+=/]{44}")?;

    let request: Query = serde_qs::from_str(query_string)?;
    let key = request.key.as_str();

    ensure!(
        key_check.is_match(key),
        "`{:?}` is not a valid WireGuard key",
        key
    );

    let output = Command::new("sudo")
        .arg(wg_backbone_path)
        .arg("accept")
        .arg(request.node.to_string())
        .arg(key)
        .output()?;
    match output.status.code() {
        Some(0) => Ok((
            WireGuardInfo {
                node: request.node,
                key: key.to_string(),
                port: None,
            },
            false,
        )),
        Some(2) => Ok((
            WireGuardInfo {
                node: request.node,
                key: key.to_string(),
                port: None,
            },
            true,
        )),
        Some(c) => bail!(
            "`wg_backbone accept` failed with non-zero exit code `{:?}`",
            c
        ),
        None => bail!("`wg_backbone accept` terminated by signal"),
    }
}

fn process_request(server_info: WireGuardInfo, wg_backbone_path: &str) -> Response {
    let request_method = env::var("REQUEST_METHOD").unwrap_or_default();
    let query_string = env::var("QUERY_STRING").unwrap_or_default();

    if request_method != "GET" || query_string.is_empty() {
        return Response {
            status: Status::NotRestricted,
            server: Some(server_info),
            client: None,
            error: None,
        };
    }

    match register_wg(wg_backbone_path, &query_string) {
        Ok((client, false)) => Response {
            status: Status::RequestAccepted,
            server: Some(server_info),
            client: Some(client),
            error: None,
        },
        Ok((_, true)) => Response {
            status: Status::RequestAlreadyRegistered,
            server: Some(server_info),
            client: None,
            error: None,
        },
        Err(e) => Response {
            status: Status::RequestFailed,
            server: Some(server_info),
            client: None,
            error: Some(e.to_string()),
        },
    }
}

fn main() {
    let response = match get_server_status() {
        Ok((server_info, true, _)) => Response {
            status: Status::Restricted,
            server: Some(server_info),
            client: None,
            error: None,
        },
        Ok((server_info, false, wg_backbone_path)) => {
            process_request(server_info, &wg_backbone_path)
        }
        Err(e) => Response {
            status: Status::NotConfigured,
            server: None,
            client: None,
            error: Some(e.to_string()),
        },
    };

    println!("Content-type: application/json");
    println!();
    println!(
        "{}",
        serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string())
    );
}
