mod common;
mod config;
mod proxy;

use crate::config::Config;
use crate::proxy::VmessStream;

use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use serde_json::json;
use uuid::Uuid;
use worker::*;
use once_cell::sync::Lazy;
use regex::Regex;

static PROXYIP_PATTERN: Lazy<Regex> = Lazy::new(|| Regex::new(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[:|-](\d{1,5})$").unwrap());

async fn fetch_proxy_list(url: &str) -> Result<Vec<String>> {
    let req = Fetch::Url(Url::parse(url)?);
    let mut res = req.send().await?;
    if res.status_code() != 200 {
        return Err(Error::from(format!("Failed to fetch proxy list: HTTP {}", res.status_code())));
    }
    let text = res.text().await?;
    let lines: Vec<String> = text
        .lines()
        .filter_map(|l| {
            let parts: Vec<&str> = l.split(',').collect();
            if parts.len() >= 2 {
                let ip = parts[0].trim();
                let port = parts[1].trim();
                if !ip.is_empty() && !port.is_empty() {
                    Some(format!("{}:{}", ip, port))
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect();
    if lines.is_empty() {
        return Err(Error::from("No valid proxy entries found"));
    }
    Ok(lines)
}

#[event(fetch)]
async fn main(req: Request, env: Env, _: Context) -> Result<Response> {
    let uuid = env
        .var("UUID")
        .map(|x| Uuid::parse_str(&x.to_string()).unwrap_or_default())?;
    let host = req.url()?.host().map(|x| x.to_string()).unwrap_or_default();
    let proxy_list_url = env
        .var("PROXY_LIST_URL")
        .map(|x| x.to_string())
        .unwrap_or_else(|_| "https://raw.githubusercontent.com/ziyosen/hompage/main/ProxyList%20(1)%20(1).txt".to_string());
    let default_sni = env.var("SNI_DOMAIN").map(|x| x.to_string()).ok().unwrap_or_else(|| host.clone());

    let config = Config {
        uuid,
        host: host.clone(),
        proxy_list_url,
        proxy_addr: host.clone(),
        proxy_port: 443,
    };

    Router::with_data(config)
        .on_async("/", |_, _| welcome())
        .on_async("/link", |req, cx| link_handler(req, cx, &default_sni))
        .on_async("/:proxyip", tunnel_handler)
        .run(req, env)
        .await
}

async fn welcome() -> Result<Response> {
    Response::from_html("<h1>tunl Worker Active</h1><p>Use /link to get config or /IP:PORT (or IP-PORT) for WebSocket tunnel</p>")
}

async fn link_handler(req: Request, cx: RouteContext<Config>, default_sni: &str) -> Result<Response> {
    let url = req.url()?;
    let query_sni = url
        .query_pairs()
        .find(|(k, _)| k == "sni")
        .map(|(_, v)| v.to_string());
    let query_proxy = url
        .query_pairs()
        .find(|(k, _)| k == "proxy")
        .map(|(_, v)| v.to_string());

    let sni = query_sni.as_deref().unwrap_or(default_sni);

    let proxy_list = fetch_proxy_list(&cx.data.proxy_list_url).await?;
    let proxy = if let Some(p) = query_proxy {
        if PROXYIP_PATTERN.is_match(&p) {
            p
        } else {
            return Response::error("Invalid proxy format, use IP:PORT or IP-PORT", 400);
        }
    } else {
        let mut rand_buf = [0u8; 1];
        getrandom::getrandom(&mut rand_buf).map_err(|_| Error::from("Random gen failed"))?;
        let idx = rand_buf[0] as usize % proxy_list.len();
        proxy_list[idx].clone()
    };

    let (addr, port_str) = proxy.split_once(':').unwrap();
    let port: u16 = port_str.parse().unwrap_or(443);
    let use_tls = port == 443;

    let host = cx.data.host.clone();
    let uuid = cx.data.uuid.to_string();

    
    let path = format!("/{}", proxy.replace(':', "-"));

    let vmess_config = json!({
        "v": "2",
        "ps": "tunl",
        "add": host,                   
        "port": 443,                   
        "id": uuid,
        "aid": "0",
        "scy": "auto",
        "net": "ws",
        "type": "none",
        "host": host,
        "path": path,
        "tls": "tls",                   
        "sni": sni,
        "alpn": ""
    });
    let vmess_link = format!("vmess://{}", URL_SAFE.encode(vmess_config.to_string()));

    let response = json!({
        "vmess": vmess_link,
        "info": "Use /IP:PORT or /IP-PORT for WebSocket tunnel",
        "sni_used": sni,
        "proxy_used": proxy
    });
    Response::from_json(&response)
}

async fn tunnel_handler(req: Request, mut cx: RouteContext<Config>) -> Result<Response> {
    let proxy_param = cx.param("proxyip").unwrap().to_string();

    let captures = PROXYIP_PATTERN.captures(&proxy_param).ok_or_else(|| Error::from("Invalid proxy format. Use /IP:PORT or /IP-PORT"))?;
    let addr = captures.get(1).unwrap().as_str().to_string();
    let port: u16 = captures.get(2).unwrap().as_str().parse().map_err(|_| Error::from("Invalid port number"))?;

    cx.data.proxy_addr = addr;
    cx.data.proxy_port = port;

    let upgrade = req.headers().get("Upgrade")?.unwrap_or_default();
    if upgrade == "websocket" {
        let WebSocketPair { server, client } = WebSocketPair::new()?;
        server.accept()?;
        wasm_bindgen_futures::spawn_local(async move {
            let events = server.events().unwrap();
            if let Err(e) = VmessStream::new(cx.data, &server, events).process().await {
                console_error!("[tunnel]: {}", e);
            }
        });
        Response::from_websocket(client)
    } else {
        Response::redirect(Url::parse("https://example.com")?)
    }
}
