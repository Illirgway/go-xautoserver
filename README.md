# Go xautoserver package

Package for automatically reload TLS certificate of a running http server 
(without restarting) when such certificate is renewed (fs watch), e.g. 
[Let's Encrypt](https://letsencrypt.org/) certs and so one

Additionally, use [modern cipher suites](https://wiki.mozilla.org/index.php?title=Security/Server_Side_TLS&oldid=1212843#Modern_compatibility)
and TLS 1.2 as min TLS version

# Usage

### Simple as single package 

```gotemplate
import "github.com/Illirgway/go-xautoserver"

// ...

// xautoserver is common wrapper around http.ListenAndServer[TLS] with simple usage

func startServer(h http.Handler) error {

	var tls *xautoserver.TLSConfig = nil

	// let's say config.GetTLS() returns key and cert file paths (abs path strings)
	// and config.GetListen() returns listen address as for http.ListenAndServer

	cert, key := config.GetTLS()

	if cert != "" && key != "" {
		tls = &xautoserver.TLSConfig{
			Cert: cert,
			Key: key,
		}
	}

	// see xautoserver.Config for details	
	srvCfg := xautoserver.Config{
		// server-side timeouts
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,

		MaxHeaderBytes:	1 << 20,

		TLS:	tls,
	}

	return xautoserver.ListenAndServe(config.GetListen(), h, &srvCfg)
}

```

### Complex usage with [`go-xgracefulstop`](https://github.com/Illirgway/go-xgracefulstop)

```gotemplate
import ( 
	"github.com/Illirgway/go-xautoserver"
	"github.com/Illirgway/go-xgracefulstop"
)

func main() {

	// ...
	// let's say h is a handler function of a http.Handler type
	var h http.Handler
	
	// ...

	gs := xgracefulstop.NewGS(1, xgracefulstop.DefaultTimeout)

	if err := startServer(h, gs); err != nil && err != http.ErrServerClosed {
		log.Fatalln("Server start error:", err)
	}
	
	gs.Wait()
}

func startServer(h http.Handler, gs *xgracefulstop.GS) error {

	var tls *xautoserver.TLSConfig = nil

	// let's say config.GetTLS() returns key and cert file paths (abs path strings)
	// and config.GetListen() returns listen address as for http.ListenAndServer

	cert, key := config.GetTLS()

	if cert != "" && key != "" {
		tls = &xautoserver.TLSConfig{
			Cert: cert,
			Key: key,
		}
	}

	srvCfg := xautoserver.Config{
		// server-side timeouts
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,

		MaxHeaderBytes:	1 << 20,

		TLS:	tls,

		// important part - use xautoserver.Config callback function to pass new http srv to GS 
		SrvCb:	gs.SetServerAndWatch,	 
	}

	return xautoserver.ListenAndServe(config.GetListen(), h, &srvCfg)
}

```