use crate::record_support::{ACCOUNT, Api, ZONE};
use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use zixcel_domain::record_editor::Scope;

pub struct Client {
    writer: UnixStream,
    reader: BufReader<UnixStream>,
}
impl Client {
    pub fn request(&mut self, command: Value) -> Value {
        writeln!(
            self.writer,
            "{}",
            serde_json::json!({"protocol":1,"command":command})
        )
        .unwrap();
        let mut line = String::new();
        assert!(self.reader.read_line(&mut line).unwrap() > 0);
        serde_json::from_str(&line).unwrap()
    }
}
pub fn session(api: &mut Api, run: impl FnOnce(&mut Client)) {
    std::thread::scope(|threads| {
        let (server, client) = UnixStream::pair().unwrap();
        let worker = threads.spawn(move || {
            zixcel_domain::record_cli::serve(
                Scope {
                    account: ACCOUNT.into(),
                    zone: ZONE.into(),
                    domain: "example.test".into(),
                },
                BufReader::new(server.try_clone().unwrap()),
                server,
                api,
            )
        });
        let mut client = Client {
            reader: BufReader::new(client.try_clone().unwrap()),
            writer: client,
        };
        run(&mut client);
        assert_eq!(
            client.request(serde_json::json!({"action":"stop"}))["result"]["session_closed"],
            "requested"
        );
        drop(client);
        worker.join().unwrap().unwrap();
    });
}
