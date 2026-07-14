"""A boatramp function in Python: a `wasi:http` component. It answers every
request with a greeting -- edit `handle` to do the real work. Built to a component
with `boatramp function build` (which runs `componentize-py`)."""

from componentize_py_types import Ok
from wit_world.exports import IncomingHandler as IncomingHandlerExport
from wit_world.imports.types import (
    Fields,
    IncomingRequest,
    OutgoingBody,
    OutgoingResponse,
    ResponseOutparam,
)


class IncomingHandler(IncomingHandlerExport):
    def handle(self, request: IncomingRequest, response_out: ResponseOutparam) -> None:
        response = OutgoingResponse(Fields.from_list([("content-type", b"text/plain")]))
        response.set_status_code(200)
        body = response.body()

        # Hand the response head back to the host, then stream the body.
        ResponseOutparam.set(response_out, Ok(response))

        out = body.write()
        out.blocking_write_and_flush(b"hello from your boatramp function (py)\n")
        out.__exit__(None, None, None)
        OutgoingBody.finish(body, None)
