wit_bindgen::generate!({
    world: "edge",
    path: "wit",
});

use boatramp::composedemo::adder::add;

struct Component;

impl Guest for Component {
    fn run() -> u32 {
        // Calls the imported `adder` — satisfied by the plugin once composed.
        add(2, 3)
    }
}

export!(Component);
