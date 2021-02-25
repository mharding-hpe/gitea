// Copyright 2019 The Gitea Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package graceful

import (
    "code.gitea.io/gitea/modules/log"
	"crypto/tls"
	"net/http"
)

func newHTTPServer(network, address string, handler http.Handler) (*Server, ServeFunction) {
	server := NewServer(network, address)
	httpServer := http.Server{
		ReadTimeout:    DefaultReadTimeOut,
		WriteTimeout:   DefaultWriteTimeOut,
		MaxHeaderBytes: DefaultMaxHeaderBytes,
		Handler:        handler,
	}
	server.OnShutdown = func() {
		httpServer.SetKeepAlivesEnabled(false)
	}
	return server, httpServer.Serve
}

// HTTPListenAndServe listens on the provided network address and then calls Serve
// to handle requests on incoming connections.
func HTTPListenAndServe(network, address string, handler http.Handler) error {
    log.Trace("modules/graceful/server_http.go: HTTPListenAndServe: 1 network=%s address=%s", network, address)
	server, lHandler := newHTTPServer(network, address, handler)
    log.Trace("modules/graceful/server_http.go: HTTPListenAndServe: 2 network=%s address=%s", network, address)
	return server.ListenAndServe(lHandler)
}

// HTTPListenAndServeTLS listens on the provided network address and then calls Serve
// to handle requests on incoming connections.
func HTTPListenAndServeTLS(network, address, certFile, keyFile string, handler http.Handler) error {
    log.Trace("modules/graceful/server_http.go: HTTPListenAndServeTLS: 1 network=%s address=%s certFile=%s keyFile=%s", network, address, certFile, keyFile)
	server, lHandler := newHTTPServer(network, address, handler)
    log.Trace("modules/graceful/server_http.go: HTTPListenAndServeTLS: 2 network=%s address=%s certFile=%s keyFile=%s", network, address, certFile, keyFile)
	return server.ListenAndServeTLS(certFile, keyFile, lHandler)
}

// HTTPListenAndServeTLSConfig listens on the provided network address and then calls Serve
// to handle requests on incoming connections.
func HTTPListenAndServeTLSConfig(network, address string, tlsConfig *tls.Config, handler http.Handler) error {
    log.Trace("modules/graceful/server_http.go: HTTPListenAndServeTLSConfig: 1 network=%s address=%s tlsConfig=%v", network, address, *tlsConfig)
	server, lHandler := newHTTPServer(network, address, handler)
    log.Trace("modules/graceful/server_http.go: HTTPListenAndServeTLSConfig: 2 network=%s address=%s tlsConfig=%v", network, address, *tlsConfig)
	return server.ListenAndServeTLSConfig(tlsConfig, lHandler)
}
