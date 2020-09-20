# Traefik ForwardAuth Certificates

Returns the certificate CN, CN with Regex applied, or DN in the header as enviroment variable.

## Usage
Run the docker container, exposing port 8443, place web server certificates in `/certs/tls.key` and `/certs/tls.crt`, and set the `REQUEST_HEADER`, `RESPONSE_HEADER` and `CN_REGEX` (optional) environment variables. Configure the Elastic APM environment variables as per the documentation [here](https://www.elastic.co/guide/en/apm/agent/go/current/configuration.html#config-log-file)

See the API documentation at `/swagger/index.html`

## Traefik Configuration

Traefik's Header for the PassTLSClientCert Middleware is `X-Forwarded-Tls-Client-Cert`.
 The recommended use for this container is to create a chain of middlewares with PassTLSClientCert and then ForwardAuth, such as the following.

 ```
 apiVersion: traefik.containo.us/v1alpha1
kind: Middleware
metadata:
  name: client-cert
spec:
  passTLSClientCert:
    pem: true

```

```
# Forward authentication to example.com
apiVersion: traefik.containo.us/v1alpha1
kind: Middleware
metadata:
  name: fwdauth-certs
spec:
  forwardAuth:
    address: https://this-container.kube-system.svc.cluster.local/v1/certificate/cn
```

```
---
apiVersion: traefik.containo.us/v1alpha1
kind: Middleware
metadata:
  name: add-user-headers
spec:
  chain:
    middlewares:
    - name: client-cert
    - name: fwdauth-certs
```

Then create the ingress that uses the chain:

```
---
apiVersion: traefik.containo.us/v1alpha1
kind: IngressRoute
metadata:
  name: test
  namespace: default

spec:
  entryPoints:
    - web

  routes:
    - match: Host(`mydomain`)
      kind: Rule
      services:
        - name: whoami
          port: 80
      middlewares:
        - name: add-user-headers