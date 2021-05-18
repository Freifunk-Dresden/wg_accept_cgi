use std::env;
use std::process::Command;
use regex::Regex;
use serde_derive::Serialize;
use qstring::QString;

#[derive(Serialize)]
struct Response {
    status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    server: Option<WireguardInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client: Option<WireguardInfo>,
}

#[derive(Serialize)]
struct WireguardInfo {
    node: u16,
    key: String,
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

fn uci_get(key: &str) -> Option<String> {
    let output = Command::new("uci").arg("get").arg("-q").arg(key).output();
    if let Ok(output) = output {
        if output.status.success() {
            Some(String::from_utf8(output.stdout).unwrap_or_default())
        } else {
            None
        }
    } else {
        None
    }
}

fn register_wg(node: &str, key: &str) -> Option<(WireguardInfo, bool)> {
    let key_check = Regex::new("[0-9a-zA-Z+=/]{44}").unwrap();
    let node = node.parse::<u16>();

    if let Ok(node) = node {
        if key_check.is_match(key) {
            let output = Command::new("sudo")
                                .arg("/usr/local/bin/wg-backbone.sh")
                                .arg("accept")
                                .arg(node.to_string())
                                .arg(key)
                                .output();
            if let Ok(output) = output {
                if output.status.success() {
                    return Some((WireguardInfo{ node, key: key.to_string() }, false));
                } else if output.status.code() == Some(2) {
                    return Some((WireguardInfo{ node, key: key.to_string() }, true));
                }
            }
        }
    }
    None
}

fn print_output_and_exit(response: &Response) {
    println!("Content-type: application/json");
    println!();
    println!("{}", serde_json::to_string(&response).unwrap_or("{}".to_string()));

    std::process::exit(0x0);
}

fn main() {

    let server_key = uci_get("ffdd.wireguard.public").unwrap_or_default().replace("\n", "");
    let server_node = uci_get("ffdd.sys.ddmesh_node").unwrap_or_default().replace("\n", "");
    let server_restricted = uci_get("ffdd.sys.wireguard_restrict").unwrap_or_default().replace("\n", "");
    let server_restricted = server_restricted.trim();

    if server_key.is_empty() || server_node.is_empty() || server_restricted.is_empty() {
        let response = Response{ status: Status::NotConfigured, server: None, client: None };
        print_output_and_exit(&response);
    }

    let server = Some(WireguardInfo {
        node: server_node.parse::<u16>().unwrap(),
        key: server_key,
    });

    let request_method = env::var("REQUEST_METHOD").unwrap_or_default();
    let query_string = env::var("QUERY_STRING").unwrap_or_default();

    if server_restricted != "1" && request_method == "GET" && !query_string.is_empty() {

        let qs = QString::from(&format!("?{}", query_string)[..]);
        let client_key = qs.get("key").unwrap_or_default();
        let client_node = qs.get("node").unwrap_or_default();
        
        let response = match register_wg(client_node, client_key) {
            Some((client, false)) => {
                Response{ status: Status::RequestAccepted, server, client: Some(client) }
            },
            Some((_, true)) => {
                Response{ status: Status::RequestAlreadyRegistered, server, client: None }
            },
            None => {
                Response{ status: Status::RequestFailed, server, client: None }
            },
        };
        print_output_and_exit(&response);
        return;
    }

    let response = if server_restricted == "1" {
        Response{ status: Status::Restricted, server, client: None }
    } else {
        Response{ status: Status::NotRestricted, server, client: None }
    };
    print_output_and_exit(&response);
}