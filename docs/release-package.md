# Release packages

Sentinel Cortex publishes release-candidate assets while the autonomous branch is being hardened.

Each RC includes:

- `cortex` standalone analyzer binaries for Linux, macOS and Windows;
- `cortex-agent` autonomous daemon binaries for Linux amd64 and arm64;
- a Helm chart (`sentinel-cortex-*.tgz`);
- `SHA256SUMS` for every downloadable asset;
- a multi-architecture OCI image at `ghcr.io/riccardomenegazzo/kernel-sentinel-cortex-agent`.

## Binary package

Download the archive matching your OS/architecture, verify it against `SHA256SUMS`, unpack it and run the binary. The agent archives also include `config.example.json`.

## Helm install

Autonomous execution is disabled by default:

```bash
helm install cortex sentinel-cortex-0.1.0.tgz \
  --namespace cortex-system --create-namespace \
  --set target.namespace=production \
  --set target.deployment=checkout \
  --set target.service=checkout
```

Before enabling mutations, provide a persistent audit HMAC secret and review the generated Role in the target namespace:

```bash
kubectl -n cortex-system create secret generic cortex-audit \
  --from-literal=hmac="$(openssl rand -hex 32)"

helm upgrade cortex sentinel-cortex-0.1.0.tgz \
  --namespace cortex-system \
  --reuse-values \
  --set audit.existingSecret=cortex-audit \
  --set autonomy.execute=true \
  --set autonomy.allowMutations=true
```

The two independent mutation flags are intentional. The daemon also fails closed if durable audit configuration is absent.
