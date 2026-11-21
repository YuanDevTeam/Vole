//! Real H1 framing + actual system JSC, with only in-memory peer I/O.
use super::*;

async fn exchange(yaml: &str, request: &[u8]) -> (String, Arc<Origin>) {
    exchange_policy(Policy::compile(yaml).unwrap(), request).await
}

async fn exchange_policy(policy: Arc<Policy>, request: &[u8]) -> (String, Arc<Origin>) {
    let origin = Arc::new(Origin::default());
    let context = HttpContext::new(policy, origin.clone(), SecurityContext::new());
    let (mut client, mut server) = tokio::io::duplex(16 * 1024);
    let task = tokio::spawn(async move {
        context
            .serve_h1(
                &mut server,
                session(),
                Scheme::Http,
                CancellationToken::new(),
            )
            .await
            .unwrap();
    });
    client.write_all(request).await.unwrap();
    let mut response = String::new();
    timeout(Duration::from_secs(5), client.read_to_string(&mut response))
        .await
        .unwrap()
        .unwrap();
    task.await.unwrap();
    origin.join().await;
    (response, origin)
}

#[tokio::test]
async fn request_script_sees_native_headers_and_responds_without_upstream() {
    let (response, origin) = exchange(
        r#"
targets:
  - origins: [http://old.invalid]
    rules:
      - request:
          headers:
            - {set: {X-Native: ready}}
      - name: local
        request:
          js:
            source: |
              function rewrite(input) {
                let found = false;
                for (let i=0;i<input.request.headers.length;i++) {
                  if(input.request.headers[i].name === "x-native") found=true;
                }
                if(!found) return {type:"abort"};
                return {type:"respond",status:200,body:{kind:"text",data:"local-jsc"}};
              }
"#,
        b"GET /a HTTP/1.1\r\nHost: old.invalid\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.ends_with("\r\n\r\nlocal-jsc"), "{response}");
    assert!(origin.sessions.lock().unwrap().is_empty());
}

#[tokio::test]
async fn staged_response_scripts_read_frozen_typed_parameters() {
    use super::config::{Document, ParameterValue, PluginInput, PluginPermissions};
    use sha2::{Digest as _, Sha256};

    let yaml = r#"
parameters:
  enabled: {type: boolean, default: true}
  profile: {type: string, default: stable, choices: [stable, beta]}
  version: {type: integer, default: 3}
targets:
  - origins: [http://old.invalid]
    rules:
      - request:
          headers:
            - set: {X-Mode: changed}
        response:
          headers:
            - set: {X-Native: {param: profile}}
      - request:
          js:
            source: |
              function rewrite(input) {
                return {type: "modify", url: "http://unauthorized.invalid/redirect",
                  headers: [{op: "set", name: "x-unauthorized", values: ["leaked"]}]};
              }
      - request:
          js:
            source: |
              function rewrite(input) {
                return {type: "modify", url: "http://old.invalid/same-origin"};
              }
      - match:
          request-headers:
            - {name: X-Mode, equals: original}
          parameters: {enabled: true}
        response:
          when: {status: 200}
          js:
            source: |
              function rewrite(input) {
                input.parameters.profile = "forbidden";
                return {type: "abort"};
              }
      - match:
          request-headers:
            - {name: X-Mode, equals: original}
        response:
          when: {status: 200}
          js:
            source: |
              function rewrite(input) {
                if (!input.parameters.enabled || input.parameters.version !== 3)
                  return {type: "abort"};
                return {type: "modify", headers: [
                  {op: "set", name: "x-script-profile", values: [input.parameters.profile]}
                ]};
              }
      - response:
          when:
            headers:
              - {name: X-Native, exists: true}
          js:
            source: 'function rewrite(input) { return {type:"abort"}; }'
"#;
    let policy = Document::parse_managed(&[PluginInput {
        id: "managed-http-test".into(),
        digest: Sha256::digest(yaml.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        yaml: yaml.into(),
        parameters: [("profile".into(), ParameterValue::String("beta".into()))].into(),
        permissions: PluginPermissions {
            js: true,
            ..Default::default()
        },
    }])
    .unwrap()
    .static_policy()
    .unwrap();
    let (response, origin) = exchange_policy(
        policy,
        b"GET /a HTTP/1.1\r\nHost: old.invalid\r\nX-Mode: original\r\nConnection: close\r\n\r\n",
    )
    .await;
    let response = response.to_ascii_lowercase();
    assert!(response.starts_with("http/1.1 200"), "{response}");
    assert!(response.contains("x-native: beta\r\n"), "{response}");
    assert!(
        response.contains("x-script-profile: beta\r\n"),
        "{response}"
    );
    assert!(response.ends_with("\r\n\r\nok"), "{response}");
    assert_eq!(origin.sessions.lock().unwrap().len(), 1);
    let heads = origin.heads.lock().unwrap();
    assert!(
        heads[0].starts_with("GET /same-origin HTTP/1.1"),
        "{heads:?}"
    );
    assert!(!heads[0].contains("x-unauthorized"), "{heads:?}");
}

#[tokio::test]
async fn response_native_then_scripts_preserve_success_before_invalid_output() {
    let (response,origin)=exchange(r#"
targets:
  - origins: [http://old.invalid]
    rules:
      - response:
          body:
            - {set: native}
      - name: change
        response:
          js:
            body: text
            source: 'function rewrite(input) {return {type:"modify",body:{kind:"text",data:input.body.data+":js"}};}'
      - name: invalid
        response:
          js:
            body: text
            source: 'function rewrite(input) {return {type:"modify",headers:[{op:"set",name:"Content-Length",values:["1"]}],body:{kind:"text",data:"bad"}};}'
      - name: final
        response:
          js:
            source: 'function rewrite(input) {return {type:"modify",status:201,headers:[{op:"add",name:"x-final",values:["yes"]}]};}'
"#,b"GET /a HTTP/1.1\r\nHost: old.invalid\r\nConnection: close\r\n\r\n").await;
    assert!(response.starts_with("HTTP/1.1 201"), "{response}");
    assert!(
        response.to_ascii_lowercase().contains("x-final: yes\r\n"),
        "{response}"
    );
    assert!(response.ends_with("\r\n\r\nnative:js"), "{response}");
    assert_eq!(origin.sessions.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn request_url_scripts_match_u0_and_only_connect_the_final_target() {
    let (response,origin)=exchange(r#"
targets:
  - origins: [http://old.invalid]
    rules:
      - request:
          url: {replace: {value: http://middle.invalid/, mode: match}}
      - name: original
        request:
          js:
            source: 'function rewrite(input) {return {type:"modify",url:"http://final.invalid:8081/end",headers:[{op:"set",name:"Authorization",values:["Bearer final"]}]};}'
  - origins: [http://final.invalid:8081]
    rules:
      - name: should-not-match
        request:
          js:
            source: 'function rewrite(input) {return {type:"abort"};}'
"#,b"GET /a HTTP/1.1\r\nHost: old.invalid\r\nAuthorization: old-secret\r\nCookie: old-cookie\r\nConnection: close\r\n\r\n").await;
    assert!(response.ends_with("\r\n\r\nok"));
    let sessions = origin.sessions.lock().unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(
        sessions[0].destination,
        Destination::domain("final.invalid", 8081).unwrap()
    );
    let heads = origin.heads.lock().unwrap();
    assert!(heads[0].starts_with("GET /end HTTP/1.1"));
    assert!(
        heads[0]
            .to_ascii_lowercase()
            .contains("authorization: bearer final")
    );
    assert!(!heads[0].contains("old-secret"));
    assert!(!heads[0].contains("old-cookie"));
}
