// Runnable manual verification of the generated Web/TypeScript connect-es client against a LIVE
// boatramp Connect service (PLAN-connect-grpc §9 / IU-5).
//
// This is the Web/TS counterpart of the Rust client live gates. It is NOT a CI gate: a browser/node
// connect-web round trip needs a standing boatramp Connect endpoint (the Rust gates spin the server
// in-process, which a separate node process cannot reuse), so instead of faking a passing gate we
// ship this runnable script + the `npm run typecheck` signal (which proves the generated client +
// the pinned connect runtime types + this script all agree, with no live endpoint).
//
// To run it for real:
//   1. Stand up a boatramp Connect endpoint serving `connect.greeter.v1.Greeter` (unary) and
//      `connect.ticker.v1.Ticker` (server-stream) — e.g. deploy the shim repo's `connect-greeter`
//      and `connect-ticker` example guests to a site, or point at any boatramp site that serves
//      those services.
//   2. From `clients/ts/`: `npm ci`
//   3. BOATRAMP_CONNECT_URL=https://<host>/_sites/<site> [BOATRAMP_TOKEN=<token>] npm run verify
//
// It calls the generated `Greeter.SayHello` and `Ticker.Subscribe` over connect-web with the BINARY
// proto codec (not JSON) and asserts the round trips.

import { createClient, type Interceptor } from "@connectrpc/connect";
import { createConnectTransport } from "@connectrpc/connect-web";
import { Greeter } from "./generated/connect/greeter/v1/greeter_pb.js";
import { Ticker } from "./generated/connect/ticker/v1/ticker_pb.js";

const baseUrl = process.env.BOATRAMP_CONNECT_URL;
if (!baseUrl) {
  console.error(
    "set BOATRAMP_CONNECT_URL (e.g. https://host/_sites/site) to run the live verification",
  );
  process.exit(2);
}
const token = process.env.BOATRAMP_TOKEN;

// Attach the boatramp bearer token (the only boatramp-specific request bit — see
// docs/src/reference/connect-grpc-clients.md).
const authInterceptor: Interceptor = (next) => async (req) => {
  if (token) {
    req.header.set("Authorization", `Bearer ${token}`);
  }
  return await next(req);
};

const transport = createConnectTransport({
  baseUrl,
  // Binary proto over connect-web (the JSON codec is a deferred ergonomics add — PLAN §1).
  useBinaryFormat: true,
  interceptors: [authInterceptor],
});

async function main(): Promise<void> {
  // ---- unary ----
  const greeter = createClient(Greeter, transport);
  const reply = await greeter.sayHello({ name: "boatramp" });
  console.log(`unary: Greeter.SayHello -> ${reply.greeting}`);
  if (reply.greeting !== "hello, boatramp!") {
    throw new Error(`unexpected greeting: ${reply.greeting}`);
  }

  // ---- server-stream ----
  const ticker = createClient(Ticker, transport);
  let seen = 0n;
  for await (const tick of ticker.subscribe({ count: 4 })) {
    seen += 1n;
    console.log(`server-stream: Ticker.Subscribe -> seq=${tick.seq} note=${tick.note}`);
    if (tick.seq !== seen) {
      throw new Error(`out-of-order tick: expected seq ${seen}, got ${tick.seq}`);
    }
  }
  if (seen !== 4n) {
    throw new Error(`expected 4 ticks, saw ${seen}`);
  }

  console.log("CONNECT WEB CLIENT LIVE OK");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
