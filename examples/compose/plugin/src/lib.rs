wit_bindgen::generate!({
    world: "plugin",
    path: "wit",
});

struct Component;

impl exports::boatramp::composedemo::adder::Guest for Component {
    fn add(a: u32, b: u32) -> u32 {
        a + b
    }
}

export!(Component);
