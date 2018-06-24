# check\_goversion

A Nagios plugin for ensuring that you're running the latest version of Go inspired by a conversation I saw on Twitter: https://twitter.com/miekg/status/1010589700829188096

## Usage:

Your app must have some sort of health information expressed in JSON exposed via HTTP. For example, my app may use [healthz](https://github.com/jasonhancock/healthz) and expose a page that looks like this:

```
{
	"app": {
		"metadata": {
			"build_version": "1.0.1234",
			"git_hash": "0274ba9",
			"go_version": "go1.10.3"
		}
	}
}
```

Let's assume this page is hosted at http://example.com/healthz

You could then run:

```
./check_goversion -endpoint http://example.com/healthz -endpoint-path app.metadata.go_version
```

The plugin would then extract the version number from your application's health page and compare it to the latest go version as obtained at https://golang.org/VERSION?m=text, throwing a critical error if they don't match.
