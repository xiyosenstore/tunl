// src/config.rs
use uuid::Uuid;

pub struct Config {
    pub uuid: Uuid,
    pub host: String,               
    pub proxy_list_url: String,     
    pub proxy_addr: String,         
    pub proxy_port: u16,            
}
