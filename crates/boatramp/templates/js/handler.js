// A boatramp function in JavaScript: a `wasi:http` component. It answers every
// request with a greeting — edit `handle` to do the real work. Built to a
// component with `boatramp function build` (which runs `jco componentize`).

import {
  Fields,
  OutgoingBody,
  OutgoingResponse,
  ResponseOutparam,
} from "wasi:http/types@0.2.0";

export const incomingHandler = {
  handle(_request, responseOut) {
    const response = new OutgoingResponse(new Fields());
    response.setStatusCode(200);
    const body = response.body();

    // Hand the response head back to the host, then stream the body.
    ResponseOutparam.set(responseOut, { tag: "ok", val: response });

    const message = "hello from your boatramp function (js)\n";
    const stream = body.write();
    stream.blockingWriteAndFlush(new TextEncoder().encode(message));
    stream[Symbol.dispose]();
    OutgoingBody.finish(body, undefined);
  },
};
