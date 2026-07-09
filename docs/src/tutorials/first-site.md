# Publish your first site

In this tutorial you run a boatramp server, publish a one-page site, and load it
— using only the files you create here. No build tool, no account, no config. By
the end you will have published an immutable deployment and served it over HTTP.

You need the `boatramp` binary on your `PATH`. If you do not have it yet, see
[Install boatramp](../how-to/install.md).

## 1. Create a site folder

Make a folder with one HTML file:

```sh
mkdir my-site
cat > my-site/index.html <<'HTML'
<!doctype html>
<title>Hello from boatramp</title>
<h1>It works.</h1>
HTML
```

## 2. Start the server

In one terminal, run the server. With no arguments it serves plain HTTP on
`127.0.0.1:8080` and stores data under `./data` — enough for this tutorial:

```sh
boatramp serve
```

```text
serving http://127.0.0.1:8080 — data ./data
```

Leave it running and open a second terminal for the next steps.

## 3. Publish the folder

Publish `my-site` as a deployment. `sync` uploads the files, records a manifest,
and activates the site — all at once:

```sh
boatramp sync ./my-site --server http://127.0.0.1:8080 --site my-site
```

```text
scanned 1 file(s), 1 unique blob(s)
uploading 1 missing blob(s)… done
activated my-site -> 3b1c9f0a
```

## 4. Load it

Fetch the site. Every site answers on `/sites/<name>/`:

```sh
curl http://127.0.0.1:8080/sites/my-site/
```

```text
<!doctype html>
<title>Hello from boatramp</title>
<h1>It works.</h1>
```

You have published and served your first site.

## 5. Change and republish

Edit the page and publish again. Only the changed file uploads, and the site
flips to the new deployment atomically:

```sh
echo '<h1>Second deploy.</h1>' > my-site/index.html
boatramp sync ./my-site --server http://127.0.0.1:8080 --site my-site
```

```text
scanned 1 file(s), 1 unique blob(s)
uploading 1 missing blob(s)… done
activated my-site -> 7d42a1e8
```

`curl` the site again and you get the new page. The previous deployment still
exists — [Publish, roll back, and alias a site](../how-to/publish.md) shows how
to roll back to it in one command.

## Where to go next

- Put it on a real hostname over HTTPS:
  [Attach a custom domain](../how-to/custom-domain.md) and
  [Get an automatic certificate](../how-to/acme-cert.md).
- Run it as a real service:
  [Deploy a single node in production](../how-to/deploy-single-node.md).
- Add dynamic routes: [Write your first handler](./first-handler.md).
