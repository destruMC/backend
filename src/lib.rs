use aes_gcm::aead::{Aead, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Key, KeyInit, Nonce};
use base64::Engine;
use jwt_simple::prelude::{Claims, Clock, Duration, RS256KeyPair, RSAKeyPairLike};
use reqwest::header::{ACCEPT, USER_AGENT};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqids::Sqids;
use std::collections::HashMap;
use worker::*;

const MAGIC_VALUE: u64 = 557;
const STRUCTURE_MV: u8 = 0;

const LOGIN_URL: &str = r"https://github.com/login/oauth/access_token";
const USER_URL: &str = r"https://api.github.com/user";
const TOKEN_URL: &str = r"https://api.github.com/app/installations/{}/access_tokens";
const GRAPHQL_URL: &str = r"https://api.github.com/graphql";
const OAUTH_URL: &str = r"https://api.github.com/applications/{}/token";

const STRUCTURES_QUERY: &str = r#"query($size: Int!, $cursor: String) { repository(owner: "destruMC", name: "repo") { discussions(categoryId: "DIC_kwDOObsL9c4CpOgI", first: $size, after: $cursor) { nodes { number title body author { login avatarUrl } } pageInfo { hasNextPage endCursor } } } }"#;
const STRUCTURE_QUERY: &str = r#"query($number: Int!) { repository(owner: "destruMC", name: "repo") { discussion(number: $number) { title body author { login avatarUrl } } } }"#;

#[derive(Serialize)]
struct UserResponse {
    id: String,
    name: String,
    avatar: String,
}

#[derive(Serialize)]
struct LoginResponse {
    user: UserResponse,
    token: String,
    expires: i64,
}

#[derive(Serialize)]
struct StructurePreview {
    id: String,
    name: String,
    image: String,
    author: String,
}

#[derive(Serialize)]
struct Page {
    next: bool,
    cursor: Option<String>,
}

#[derive(Serialize)]
struct StructuresResponse {
    structures: Vec<StructurePreview>,
    page: Page,
}

#[derive(Serialize)]
struct GraphqlQuery {
    query: String,
    variables: serde_json::Value,
}

#[derive(Serialize)]
struct Author {
    id: String,
    avatar: String,
}

#[derive(Serialize)]
struct StructureResponse {
    name: String,
    summary: String,
    description: String,
    file: String,
    images: Vec<String>,
    author: Author,
}

#[derive(Serialize, Deserialize)]
struct Body {
    summary: String,
    description: String,
    file: String,
    images: Vec<String>,
}

#[event(fetch)]
async fn fetch(
    req: Request,
    env: Env,
    _ctx: Context,
) -> Result<Response> {
    console_error_panic_hook::set_once();

    let mut response = Router::new()
        .get_async("/login", |req, ctx| async move {
            let client_id = ctx.env.var("CLIENT_ID")?.to_string();
            let client_secret = ctx.env.secret("CLIENT_SECRET")?.to_string();
            let key = ctx.env.secret("KEY")?.to_string();

            let code = match req
                .url()
                .unwrap()
                .query_pairs()
                .find(|(key, _)| key == "code")
                .map(|(_, value)| value.to_string())
            {
                Some(value) => value,
                None => return Ok(ResponseBuilder::new().with_status(400).empty()),
            };

            let client = Client::new();

            let login_response = match client
                .post(LOGIN_URL)
                .json(&json!({
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "code": code,
                }))
                .header("Accept", "application/vnd.github+json")
                .send()
                .await
            {
                Ok(response) => response,
                Err(_) => return Ok(ResponseBuilder::new().with_status(500).empty()),
            };

            let login_data: serde_json::Value = match login_response
                .json()
                .await
            {
                Ok(response) => response,
                Err(_) => return Ok(ResponseBuilder::new().with_status(500).empty()),
            };

            let access_token = match login_data["access_token"]
                .as_str()
            {
                Some(value) => value,
                None => return Ok(ResponseBuilder::new().with_status(500).empty()),
            };

            let refresh_token = match login_data["refresh_token"]
                .as_str()
            {
                Some(value) => value,
                None => return Ok(ResponseBuilder::new().with_status(500).empty()),
            };

            let refresh_token_expires_in = match login_data["refresh_token_expires_in"]
                .as_i64()
            {
                Some(value) => value,
                None => return Ok(ResponseBuilder::new().with_status(500).empty()),
            };

            let user_response = match client
                .get(USER_URL)
                .bearer_auth(access_token)
                .header(USER_AGENT, "destru")
                .send()
                .await
            {
                Ok(response) => response,
                Err(_) => return Ok(ResponseBuilder::new().with_status(500).empty()),
            };

            let user_data: serde_json::Value = match user_response
                .json()
                .await
            {
                Ok(response) => response,
                Err(_) => return Ok(ResponseBuilder::new().with_status(500).empty()),
            };

            let login = match user_data["login"]
                .as_str()
            {
                Some(value) => value,
                None => return Ok(ResponseBuilder::new().with_status(500).empty()),
            };

            let name = user_data["name"]
                .as_str()
                .unwrap_or(login);

            let avatar_url = user_data["avatar_url"]
                .as_str()
                .unwrap_or("");
            
            let refresh_token = match encrypt(&*key, refresh_token)
            {
                Some(refresh_token) => refresh_token,
                None => return Ok(ResponseBuilder::new().with_status(500).empty()),
            };

            ResponseBuilder::new()
                .ok(serde_json::to_string(&LoginResponse {
                    user: UserResponse {
                        id: login.to_string(),
                        name: name.to_string(),
                        avatar: avatar_url.to_string(),
                    },
                    token: refresh_token,
                    expires: refresh_token_expires_in,
                }).unwrap())
        })
        .get_async("/structures", |req, ctx| async move {
            let client_id = ctx.env.var("CLIENT_ID")?.to_string();
            let installation_id = ctx.env.var("INSTALLATION_ID")?.to_string();
            let private_key = ctx.env.secret("PRIVATE_KEY")?.to_string();

            let url = req.url().unwrap();
            let params: HashMap<_, _> = url.query_pairs().into_owned().collect();

            let size: Option<u8> = params.get("size").and_then(|v| v.parse().ok());
            let cursor: Option<String> = params.get("cursor").cloned();

            let client = Client::new();

            let token = match get_app_access_token(&client, &*client_id, &*installation_id, &*private_key)
                .await
            {
                Some(token) => token,
                None => return Ok(ResponseBuilder::new().with_status(500).empty()),
            };

            let response = match client
                .post(GRAPHQL_URL)
                .json(&GraphqlQuery {
                    query: STRUCTURES_QUERY.to_string(),
                    variables: json!({
                        "size": size.unwrap_or(20),
                        "cursor": cursor,
                    })
                })
                .bearer_auth(token)
                .header(USER_AGENT, "destru")
                .send()
                .await
            {
                Ok(response) => response,
                Err(_) => return Ok(ResponseBuilder::new().with_status(500).empty()),
            };

            let json: serde_json::Value = match response
                .json()
                .await
            {
                Ok(json) => json,
                Err(_) => return Ok(ResponseBuilder::new().with_status(500).empty()),
            };

            let discussions = &json["data"]["repository"]["discussions"];
            let empty = vec![];
            let nodes = discussions["nodes"].as_array().unwrap_or(&empty);
            let structures: Vec<StructurePreview> = nodes.iter().filter_map(|node| {
                let body = extract_body(node)?;
                Some(StructurePreview {
                    id: encode_sqids(STRUCTURE_MV, node["number"].as_i64().unwrap())?.to_string(),
                    name: node["title"].as_str()?.to_string(),
                    image: body.images[0].to_string(),
                    author: node["author"]["login"].as_str()?.to_string(),
                })
            }).collect();
            let page_info = &discussions["pageInfo"];
            let page = Page {
                next: page_info["hasNextPage"].as_bool().unwrap_or(false),
                cursor: page_info["endCursor"].as_str().map(|s| s.to_string()),
            };

            Response::ok(
                serde_json::to_string(&StructuresResponse {
                    structures,
                    page,
                })
                    .unwrap())
        })
        .get_async("/structures/:id", |_req, ctx| async move {
            let client_id = ctx.env.var("CLIENT_ID")?.to_string();
            let installation_id = ctx.env.var("INSTALLATION_ID")?.to_string();
            let private_key = ctx.env.secret("PRIVATE_KEY")?.to_string();

            let id = match ctx.param("id") {
                Some(value) => value.as_str(),
                None => return Ok(ResponseBuilder::new().with_status(400).empty()),
            };
            let id = match decode_sqids(STRUCTURE_MV, id) {
                Some(id) => {
                    if id == -1 {
                        return Ok(ResponseBuilder::new().with_status(404).empty())
                    }
                    id
                },
                None => return Ok(ResponseBuilder::new().with_status(500).empty()),
            };

            let client = Client::new();

            let token = match get_app_access_token(&client, &*client_id, &*installation_id, &*private_key)
                .await
            {
                Some(token) => token,
                None => return Ok(ResponseBuilder::new().with_status(500).empty()),
            };

            let response = match client
                .post(GRAPHQL_URL)
                .json(&GraphqlQuery {
                    query: STRUCTURE_QUERY.to_string(),
                    variables: json!({
                        "number": id,
                    })
                })
                .bearer_auth(token)
                .header(USER_AGENT, "destru")
                .send()
                .await
            {
                Ok(response) => response,
                Err(_) => return Ok(ResponseBuilder::new().with_status(500).empty()),
            };

            let json: serde_json::Value = match response
                .json()
                .await
            {
                Ok(json) => json,
                Err(_) => return Ok(ResponseBuilder::new().with_status(500).empty()),
            };

            let json = &json["data"]["repository"]["discussion"];

            let body = match extract_body(&json)
            {
                Some(body) => body,
                None => return Ok(ResponseBuilder::new().with_status(404).empty()),
            };

            let author = &json["author"];

            Response::ok(
                serde_json::to_string(&StructureResponse {
                    name: json["title"].as_str().unwrap_or("").to_string(),
                    summary: body.summary,
                    description: body.description,
                    file: body.file,
                    images: body.images,
                    author: Author {
                        id: author["login"].as_str().unwrap_or("").to_string(),
                        avatar: author["avatarUrl"].as_str().unwrap_or("").to_string(),
                    }
                })
                .unwrap())
        })
        .get_async("/auth", |req, ctx| async move {
            let client_id = ctx.env.var("CLIENT_ID")?.to_string();
            let client_secret = ctx.env.secret("CLIENT_SECRET")?.to_string();
            let key = ctx.env.secret("KEY")?.to_string();

            let token = match req
                .url()
                .unwrap()
                .query_pairs()
                .find(|(key, _)| key == "token")
                .map(|(_, value)| value.to_string())
            {
                Some(value) => value,
                None => return Ok(ResponseBuilder::new().with_status(401).empty()),
            };

            let refresh_token = decrypt(&*key, &*token).unwrap_or("".to_string());

            let client = Client::new();

            let login_response = match client
                .post(LOGIN_URL)
                .json(&json!({
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                }))
                .header(ACCEPT, "application/vnd.github+json")
                .send()
                .await
            {
                Ok(response) => response,
                Err(_) => return Ok(ResponseBuilder::new().with_status(500).empty()),
            };

            let login_data: serde_json::Value = match login_response
                .json()
                .await
            {
                Ok(response) => response,
                Err(_) => return Ok(ResponseBuilder::new().with_status(500).empty()),
            };

            let access_token = match login_data["access_token"]
                .as_str()
            {
                Some(value) => value,
                None => return Ok(ResponseBuilder::new().with_status(500).empty()),
            };

            let refresh_token = match login_data["refresh_token"]
                .as_str()
            {
                Some(value) => value,
                None => return Ok(ResponseBuilder::new().with_status(500).empty()),
            };

            let refresh_token_expires_in = match login_data["refresh_token_expires_in"]
                .as_i64()
            {
                Some(value) => value,
                None => return Ok(ResponseBuilder::new().with_status(500).empty()),
            };

            let user_response = match client
                .get(USER_URL)
                .bearer_auth(access_token)
                .header(USER_AGENT, "destru")
                .send()
                .await
            {
                Ok(response) => response,
                Err(_) => return Ok(ResponseBuilder::new().with_status(500).empty()),
            };

            let user_data: serde_json::Value = match user_response
                .json()
                .await
            {
                Ok(response) => response,
                Err(_) => return Ok(ResponseBuilder::new().with_status(500).empty()),
            };

            let login = match user_data["login"]
                .as_str()
            {
                Some(value) => value,
                None => return Ok(ResponseBuilder::new().with_status(500).empty()),
            };

            let name = user_data["name"]
                .as_str()
                .unwrap_or(login);

            let avatar_url = user_data["avatar_url"]
                .as_str()
                .unwrap_or("");

            let refresh_token = match encrypt(&*key, refresh_token)
            {
                Some(refresh_token) => refresh_token,
                None => return Ok(ResponseBuilder::new().with_status(500).empty()),
            };

            ResponseBuilder::new()
                .ok(serde_json::to_string(&LoginResponse {
                    user: UserResponse {
                        id: login.to_string(),
                        name: name.to_string(),
                        avatar: avatar_url.to_string(),
                    },
                    token: refresh_token,
                    expires: refresh_token_expires_in,
                }).unwrap())
        })
        .get_async("/logout",  |req, ctx| async move {
            let client_id = ctx.env.var("CLIENT_ID")?.to_string();
            let client_secret = ctx.env.secret("CLIENT_SECRET")?.to_string();
            let key = ctx.env.secret("KEY")?.to_string();

            let token = match req
                .url()
                .unwrap()
                .query_pairs()
                .find(|(key, _)| key == "token")
                .map(|(_, value)| value.to_string())
            {
                Some(value) => value,
                None => return Ok(ResponseBuilder::new().with_status(401).empty()),
            };

            let refresh_token = decrypt(&*key, &*token).unwrap_or("".to_string());

            let client = Client::new();

            let login_response = match client
                .post(LOGIN_URL)
                .json(&json!({
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                }))
                .header(ACCEPT, "application/vnd.github+json")
                .send()
                .await
            {
                Ok(response) => response,
                Err(_) => return Ok(ResponseBuilder::new().with_status(500).empty()),
            };

            let login_data: serde_json::Value = match login_response
                .json()
                .await
            {
                Ok(response) => response,
                Err(_) => return Ok(ResponseBuilder::new().with_status(500).empty()),
            };

            let access_token = match login_data["access_token"]
                .as_str()
            {
                Some(value) => value,
                None => return Ok(ResponseBuilder::new().with_status(500).empty()),
            };

            let oauth_response = match client
                .delete(OAUTH_URL)
                .header(ACCEPT, "application/vnd.github+json")
                .header(USER_AGENT, "destru")
                .basic_auth(client_id, Some(client_secret))
                .json(&json!({
                    "access_token": access_token,
                }))
                .send()
                .await
            {
                Ok(response) => response,
                Err(_) => return Ok(ResponseBuilder::new().with_status(500).empty()),
            };

            return if oauth_response.status() == 204 {
                Response::empty()
            } else {
                Ok(ResponseBuilder::new().with_status(500).empty())
            };
        })
        .run(req, env)
        .await?;

    let headers = response.headers_mut();
    headers.set("Access-Control-Allow-Origin", "*")?;
    headers.set("Access-Control-Allow-Methods", "GET")?;
    headers.set("Access-Control-Allow-Headers", "*")?;
    Ok(response)
}

async fn get_app_access_token(reqwest: &Client, client_id: &str, installation_id: &str, private_key: &str) -> Option<String> {
    let key = RS256KeyPair::from_pem(&private_key).ok()?;

    let mut claims = Claims::create(Duration::from_mins(1));
    claims.issued_at = Some(Clock::now_since_epoch());
    claims.issuer = Some(client_id.to_string());

    let jwt = key.sign(claims).ok()?;

    let response = reqwest
        .post(TOKEN_URL.replace("{}", &*installation_id))
        .bearer_auth(jwt)
        .header(USER_AGENT, "destru")
        .send()
        .await
        .ok()?;

    let json: serde_json::Value = response
        .json()
        .await
        .ok()?;

    json["token"].as_str().map(|token| token.to_string())
}

fn get_sqids() -> sqids::Result<Sqids> {
    Sqids::builder()
        .alphabet("ABCDEFGHJKLMNPQRSTUVWXYZ123456789abcdefghijkmnopqrstuvwxyz".chars().collect())
        .min_length(6)
        .build()
}

fn encode_sqids(flag: u8, value: i64) -> Option<String> {
    if value < 0 {
        return None
    }

    let numbers = &[
        value as u64,
        MAGIC_VALUE + flag as u64,
    ];

    let sqids = get_sqids().ok()?;

    sqids.encode(numbers).ok()
}

fn decode_sqids(flag: u8, str: &str) -> Option<i64> {
    let vec = match get_sqids()
    {
        Ok(sqids) => sqids.decode(str),
        Err(_) => return None,
    };

    if vec.len() != 2 {
        return Some(-1);
    }

    let (v, m) = (vec[0], vec[1]);

    if m - MAGIC_VALUE != flag as u64 {
        return Some(-1);
    }

    if v > i64::MAX as u64 {
        return Some(-1)
    }

    Some(v as i64)
}

fn extract_body(json: &serde_json::Value) -> Option<Body> {
    let body = json["body"]
        .as_str()?
        .strip_prefix("<!--")?
        .strip_suffix("-->")?;

    serde_json::from_str::<Body>(body).ok()
}

fn encrypt(key: &str, plaintext: &str) -> Option<String> {
    let key = key.as_bytes();
    let key = Key::<Aes256Gcm>::from_slice(key);

    let cipher = Aes256Gcm::new(&key);
    
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, plaintext.as_bytes()).ok()?;

    let mut result = nonce.to_vec();
    result.extend(ciphertext);

    Some(base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(&result))
}

fn decrypt(key: &str, ciphertext: &str) -> Option<String> {
    let key = key.as_bytes();
    let key = Key::<Aes256Gcm>::from_slice(key);

    let cipher = Aes256Gcm::new(&key);

    let data = base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(ciphertext).ok()?;
    if data.len() < 12 {
        return None
    }

    let (nonce, ciphertext) = data.split_at(12);
    let nonce = Nonce::from_slice(nonce);

    let plaintext = cipher.decrypt(nonce, ciphertext).ok()?;
    String::from_utf8(plaintext).ok()
}