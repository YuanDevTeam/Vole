//! Real H1 framing + actual system JSC, with only in-memory peer I/O.
use super::*;

async fn exchange(yaml: &str, request: &[u8]) -> (String, Arc<Origin>) {
    let origin = Arc::new(Origin::default());
    let context = HttpContext::new(
        Policy::compile(yaml).unwrap(),
        origin.clone(),
        SecurityContext::new(),
    );
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
    let (response,origin)=exchange(r#"
rewrite:
  enabled: true
  rules:
  - {url: 'http://old.invalid/', match: prefix, action: request-header-set, header: X-Native, value: ready}
http-scripts:
  enabled: true
  scripts:
  - name: local
    phase: request
    url: 'http://old.invalid/'
    match: prefix
    source: |
      function rewrite(input) {
        let found = false;
        for (let i=0;i<input.request.headers.length;i++) {
          if(input.request.headers[i].name === "x-native") found=true;
        }
        if(!found) return {type:"abort"};
        return {type:"respond",status:200,body:{kind:"text",data:"local-jsc"}};
      }
"#,b"GET /a HTTP/1.1\r\nHost: old.invalid\r\nConnection: close\r\n\r\n").await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.ends_with("\r\n\r\nlocal-jsc"), "{response}");
    assert!(origin.sessions.lock().unwrap().is_empty());
}

#[tokio::test]
async fn response_native_then_scripts_preserve_success_before_invalid_output() {
    let (response,origin)=exchange(r#"
rewrite:
  enabled: true
  rules:
  - {url: '.', action: response-body-set, value: native}
http-scripts:
  enabled: true
  scripts:
  - name: change
    phase: response
    url: '.'
    body: text
    source: 'function rewrite(input) {return {type:"modify",body:{kind:"text",data:input.body.data+":js"}};}'
  - name: invalid
    phase: response
    url: '.'
    body: text
    source: 'function rewrite(input) {return {type:"modify",headers:[{op:"set",name:"Content-Length",values:["1"]}],body:{kind:"text",data:"bad"}};}'
  - name: final
    phase: response
    url: '.'
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
rewrite:
  enabled: true
  rules:
  - {url: 'http://old.invalid/', match: prefix, action: replace, replacement: 'http://middle.invalid/'}
http-scripts:
  enabled: true
  scripts:
  - name: original
    phase: request
    url: 'http://old.invalid/'
    match: prefix
    source: 'function rewrite(input) {return {type:"modify",url:"http://final.invalid:8081/end",headers:[{op:"set",name:"Authorization",values:["Bearer final"]}]};}'
  - name: should-not-match
    phase: request
    url: 'http://final.invalid:8081/'
    match: prefix
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
