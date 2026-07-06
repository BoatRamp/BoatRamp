// A boatramp messaging consumer: the dispatcher calls `handle` once per message.
// It counts deliveries in wasi:keyvalue (so a test can observe at-least-once
// delivery), keyed by topic. A message whose payload is exactly `fail` returns
// an error — exercising the redelivery + dead-letter path. The host scopes the
// bucket to the consumer's namespace (hkv/{scope}/).
wit_bindgen::generate!({
    world: "boatramp:caps-example/consumer",
    path: "wit",
    generate_all,
});

use exports::boatramp::handlers::messaging_handler::{Error, Guest, Message};
use wasi::keyvalue::{atomics, store};

struct Component;

impl Guest for Component {
    fn handle(msg: Message) -> Result<(), Error> {
        // A poison-pill payload always fails, so the dispatcher retries it and
        // eventually dead-letters it.
        if msg.data == b"fail" {
            return Err(Error::Other("intentional consumer failure".to_string()));
        }
        let bucket = store::open("").map_err(|e| Error::Other(format!("open: {e:?}")))?;
        // One counter per topic, so a test can assert how many messages of each
        // topic were delivered (incremented once per successful handle).
        let key = format!("delivered/{}", msg.topic);
        atomics::increment(&bucket, &key, 1).map_err(|e| Error::Other(format!("increment: {e:?}")))?;
        Ok(())
    }
}

export!(Component);
