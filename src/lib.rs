use reqwest::Client;
use reqwest::header::USER_AGENT;
use serde::Serialize;
use worker::*;

const AUTH_URL: &str = "https://github.com/login/oauth/authorize";
const TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
const USER_URL: &str = "https://api.github.com/user";

#[derive(Serialize)]
struct AccessQuery {
    client_id: String,
    client_secret: String,
    code: String,
}

#[derive(Serialize)]
struct CallbackResponse {
    id: String,
    name: String,
    avatar: String,
    token: String,
    expires_in: i64,
    refresh_token_expires_in: i64,
}

#[event(fetch)]
async fn fetch(
    req: Request,
    env: Env,
    _ctx: Context,
) -> Result<Response> {
    console_error_panic_hook::set_once();

    Router::new()
        .get("/login", |_, ctx| {
            let client_id = ctx.env.var("CLIENT_ID")?.to_string();

            let mut url = Url::parse(AUTH_URL)?;

            url.query_pairs_mut()
                .append_pair("client_id", client_id.as_str());

            Response::redirect(url)
        })
        .get_async("/callback", |req, ctx| async move {
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

            let client_id = ctx.env.var("CLIENT_ID")?.to_string();
            let client_secret = ctx.env.secret("CLIENT_SECRET")?.to_string();
            let db = ctx.env.d1("DB")?;

            let client = Client::new();

            let token_response = match client
                .post(TOKEN_URL)
                .json(&AccessQuery {
                    client_id,
                    client_secret,
                    code,
                })
                .header("Accept", "application/json")
                .send()
                .await
            {
                Ok(response) => response,
                Err(_) => return Ok(ResponseBuilder::new().with_status(500).empty()),
            };

            let token_data: serde_json::Value = match token_response
                .json()
                .await
            {
                Ok(response) => response,
                Err(_) => return Ok(ResponseBuilder::new().with_status(500).empty()),
            };

            let access_token = match token_data["access_token"]
                .as_str()
            {
                Some(value) => value,
                None => return Ok(ResponseBuilder::new().with_status(500).empty()),
            };

            let expires_in = match token_data["expires_in"]
                .as_i64()
            {
                Some(value) => value,
                None => return Ok(ResponseBuilder::new().with_status(500).empty()),
            };

            let refresh_token = match token_data["refresh_token"]
                .as_str()
            {
                Some(value) => value,
                None => return Ok(ResponseBuilder::new().with_status(500).empty()),
            };

            let refresh_token_expires_in = match token_data["refresh_token_expires_in"]
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

            let node_id = match user_data["node_id"]
                .as_str()
            {
                Some(value) => value,
                None => return Ok(ResponseBuilder::new().with_status(500).empty()),
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

            let statement = match db
                .prepare(r"INSERT INTO tokens (node_id, refresh_token) VALUES (?, ?) ON CONFLICT(node_id) DO UPDATE SET refresh_token = excluded.refresh_token")
                .bind(&[node_id.into(), refresh_token.into()])
            {
                Ok(response) => response,
                Err(_) => return Ok(ResponseBuilder::new().with_status(500).empty()),
            };

            match statement
                .run()
                .await
            {
                Ok(response) => response,
                Err(_) => return Ok(ResponseBuilder::new().with_status(500).empty()),
            };

            let response = CallbackResponse {
                id: login.to_string(),
                name: name.to_string(),
                avatar: avatar_url.to_string(),
                token: access_token.to_string(),
                expires_in,
                refresh_token_expires_in,
            };

            Response::ok(serde_json::to_string(&response).unwrap())
        })
        .run(req, env)
        .await
}