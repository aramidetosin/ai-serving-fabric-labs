# serving-layer: the model-serving recipe

The recipe that serves the book's models: Chapter 6's lab places it on the rails, every chapter from 7 on serves its models with it, and Chapter 20 measures it. It runs on the book's kubeadm cluster, and on any Kubernetes cluster with Multus, the CNI macvlan and static plugins, a Gateway API implementation and enough memory for the model.

Status: built and unit-tested, and deployed by chapter 6's recorded lab (`ch06/`, whose `RESULTS.md` says what the deployment showed); chapter 7's recorded lab (`ch07/`) runs it the same way, with `make client` beside `make load`.

| File | What it is |
|---|---|
| `Makefile` | `make serve`, `make load`, `make client`, `make status`, `make render`, `make delete`, `make image`, `make test` |
| `serving.py` | reads `serving.env`, renders the manifests, deploys them and reads them back; hands the key to the load client |
| `load.py` | the load client: concurrent streaming requests, counted by how each ended (standard library only) |
| `client.py` | one chat completion as any OpenAI-compatible client sends it, given only the base URL and the key (standard library only) |
| `serving.env.example` | a `serving.env` for a cluster outside the labs |
| `image/` | `sfab/serving`: its Dockerfile, its make targets and `sfab-ready`, the readiness probes |
| `tests/` | the unit tests: no cluster, no model and no network beyond the loopback |

## `serving.env`

Every target reads one file of `KEY=value` lines. In a chapter's lab the generator writes it from the spec (`bootstrap/k8s/serving.env`, by `render/k8s.py` from the `models:` table and the `serving:` block of `spec/profile-a.yaml`), and the lab's own `make serve` and `make load` pass it here. On another cluster, copy `serving.env.example` and change what differs. It holds:

- the namespace and the labels it carries (`SERVING_NAMESPACE_LABELS`: in the labs with serving on, the internal Gateway's route label, since each Gateway admits routes only from the namespaces labelled for it), how to run kubectl (in the labs, `common/bin/sfab-kubectl <lab>`: kubectl with the cluster's admin kubeconfig on the init node, over SSH; the bastion holds no admin kubeconfig), and the DaemonSets to wait for (Multus);
- the two images (`SERVING_IMAGE`, `SERVING_KEYS_IMAGE`) and the key Secret's name, field and prefix;
- where the weights are on every node that runs a server (`SERVING_MODELS_PATH`; in the labs `/srv/models`, the models share), since the image holds no model;
- the ports, llama-server's and ggml-rpc-server's arguments, and the readiness timers;
- the rail attachments (`SERVING_NAD_NN`: name, the node NIC it rides, the rail prefix, the MTU), the models (`SERVING_MODEL_NN`: name, alias, route id, the weights' file and its size in bytes) and the placement table (`SERVING_POD_NN`: pod, model, copy, role, node, rail, attachment, rail address, decision, and optionally the pod's rail MAC; each row's pod is pod 0 of its own StatefulSet, `<controller>-0`), each a numbered table with its row count and column names; from chapter 2's lab on, the decision ids each rail attachment's annotation carries (`SERVING_NAD_DECISIONS`, `<attachment>=<id>` pairs) and the one the recipe's HTTPRoute is labelled with (`SERVING_ROUTE_DECISION`), both under `SERVING_DECISION_LABEL`;
- the HTTPRoute's Gateway, hostname and timeouts, and where `make load` runs.

`serving.py` refuses a placement that breaks the recipe's rules: every pod of a copy on one rail, one server and at least one worker per copy, every rail address inside its rail's prefix and given once, every MAC a unicast one given once, every row's pod a StatefulSet's pod 0, every model a file name and a size, and a route whose `backendRequest` timeout exceeds its `request` timeout. The failure-domain rule, that every model keeps a copy through the loss of any one GPU node and of either rail switch, is the spec's (`sfab check`, `validate.py check_placement`) and the chapter 6 audit's: a copy that fits one node sits inside it, and only a copy labeled `spans: true` in the spec, the stand-in for a model larger than one node, sits on two.

## What `make serve` deploys

1. **Waits for Multus.** Each DaemonSet `SERVING_WAIT_DAEMONSETS` names is rolled out first (Multus attaches the rails).
2. **The namespace, the rails and the models volumes.** The namespace, Pod Security `restricted`, with the labels `SERVING_NAMESPACE_LABELS` names. One macvlan NetworkAttachmentDefinition per rail the placement uses: the rail's NIC as master, bridge mode, the rail MTU, the CNI `static` IPAM plugin and no routes, so a pod's rail interface holds one connected prefix and reaches its own rail only, and the `mac` capability, so a row's MAC, when the table gives one, is the pod's on its rail (in the labs the render derives it from the rail address, so a pod made again keeps it and the rail switches learn a MAC the lab expects). The cluster interface stays the pod's default route, which is how the Gateway reaches it. For every node that runs a server, a local PersistentVolume of `SERVING_MODELS_PATH` on that node, read-only many, claimed ahead by its PersistentVolumeClaim `models-<node>` in the namespace (Pod Security `restricted` admits a claim, never a hostPath): the weights stay where the node has them, never in the image. A volume released by an earlier namespace's claim is made again, since it is only a pointer to the node's path.
3. **The key, inside the cluster.** When the key Secret is missing, a Job of `sfab/keys` (`images/keys/`) generates it, `<prefix>-<32 hex>`, and prints only its fingerprint; the Job is then removed. An existing key is never replaced. Nothing outside the cluster sees the value: `make load` reads it through kubectl and hands it to the client on a pipe.
4. **The workers, then the servers.** One StatefulSet of one replica per placement row, its pod `<row>-0` pinned to its node with `nodeSelector`, its rail address and MAC fixed in its networks annotation, so a crashed or evicted pod comes back with its name, node, address and MAC (labeled: production uses a LeaderWorkerSet or similar, per-rail device-plugin resources and cluster IPAM). The StatefulSets update on delete: serve applies the rendered template, then deletes the pods whose stamp annotation differs, and each controller makes its pod again from the template. A worker runs `ggml-rpc-server` bound to its rail address, so it listens on the rail and nowhere else. Once every worker is Ready, each server runs `llama-server` bound to the pod's own cluster address (`--host $(POD_IP)`, from the downward API), with `--rpc` naming its workers' rail addresses (and `--tensor-split` giving each of two or more workers an equal share of the layers), `--api-key-file` on the key, the model from `/models/<file>` on the models volume, read-only, and the arguments from `serving.env`. Every pod of a copy sits on the copy's rail. A copy that fits one node has its server and its worker on that node, so its RPC runs through the rail NIC's macvlan bridge and never reaches a rail switch (on hardware such a copy fits one GPU and uses no NIC at all); the one copy labeled as the stand-in for a model too large for a node spans two nodes, and its RPC to the worker on the other node crosses the rail switch. A pod whose sandbox was made again without its rail is deleted too: a node booted on a kept disk runs its pods' sandboxes again, one made before Multus's daemon has written its CNI configuration gets Cilium alone, and its network-status annotation then names another address than its own. A StatefulSet or pod no row names is removed.
5. **Readiness over the rail.** A worker is Ready while `ggml-rpc-server` listens on its rail address. A server is Ready only while llama-server answers `/health` on its pod address and, for every worker, the pod holds an RPC session to it with fewer than 3 retransmission timeouts and the worker's kernel refuses a connection to a closed port over the rail (`sfab-ready`, in the image). The probe never opens an RPC session of its own, so it never competes with the server's session to the worker. Check 3 needs the rail to answer a closed port with a TCP reset: a host filter on the rail must REJECT `tcp/50053` (the probe port) with a reset, never DROP it, or every server's check times out and every copy goes unready together. A failing server leaves its Services' endpoints about `periodSeconds` times `failureThreshold` seconds after the failure (2 times 2 in the labs), plus the time the removal takes to reach the Gateway.
6. **Services and the route.** One Service per model (all its copies' servers) and one per copy, so an answer can be traced to its copy. One HTTPRoute, on the one Gateway `serving.env` names (the internal Gateway in the labs), with a rule per model and per copy (`/<model>` and `/<model>-<copy>`, the prefix rewritten to `/`) and the request and backend timeouts from `serving.env`. It is the operator's direct path for tests; audiences reach a model through the API gateway's per-model routes, never this one (in the labs, the API gateway and the model router that `render/inference.py` renders and finish applies after the recipe: `ch06/README.md`).
7. **What the table does not use.** After the Services, a rail attachment no row names is removed. `serving.py serve --replace POD` deletes the named pods first, so their StatefulSets make them again: a server whose session to a worker cannot come back (the worker was made again under it) needs it.
8. **The read-back.** Every pod Running and Ready on its row's node, owned by its row's StatefulSet, with its rail address in its network-status annotation, and every Service's ready endpoints exactly its servers, each a `PASS` or `FAIL` line, then the `== RESULT` line. `make serve` exits non-zero on any `FAIL`.

`serving.py move --env FILE --pod POD --rail N --address A --master NIC [--mac M]` makes one pod again on another rail than its row's: its StatefulSet's template gets the new networks annotation, bind address and readiness probe, its labels still the table's, with an attachment for the rail when the table uses none, and the pod is deleted so its controller makes it from that template. It is the lab's break exercise (`ch06/breaks/6a.yaml`); `serve` puts the pod back, since its stamp then differs from the rendered one. `serving.py reroute --env FILE --pod POD --nad NAME --dst CIDR --via ADDR` makes one pod again the same way at its row's own address and MAC, but through NAME, a copy of its rail attachment whose static IPAM adds a route to CIDR via ADDR (`ch06/breaks/6b.yaml`); its interface keeps the row's name, and `serve` puts the pod back and removes the copy, an attachment no row names.

**ggml-rpc is contained, not secured.** llama.cpp's own README for the RPC example says it is a proof of concept, "fragile and insecure", and never to run the RPC server on an open network. The recipe keeps it off the cluster network: a worker binds its rail address only, the rail attachments exist only in the recipe's namespace, RBAC limits who may create pods there, and the namespace's network policy denies every pod all ingress and egress on the cluster network but the router's and the Gateways' requests to a server. Cilium's policy does not reach a macvlan rail: on the rail, the containment is the attachment, the address and the namespace, not a filter.

An OpenAI-compatible client reaches a model by its base URL, `https://<hostname>/<model>/v1` (in the labs `https://serve.ai.tarnwick.example/chat/v1`), and the key.

## What `make client` sends

One chat completion from where `make load` runs, as an OpenAI-compatible client sends it: `client.py` takes the base URL (`SERVING_LOAD_URL`, or `URL=`) and the key, and nothing else of the recipe, and sends `POST <base URL>/chat/completions` with a JSON body of the model's name, one user message and `max_tokens`, the key as a bearer token, which is the request the OpenAI client libraries send for a chat completion. It prints the request line (never the key), the HTTP status and content type, the answer's model, finish reason and text, a `PASS` or `FAIL` line for HTTP 200 with a finished answer, and the `== RESULT` line. The key reaches it as it reaches `make load`: read through kubectl, handed on a pipe into a 0600 file in the client, removed after. llama-server adds its timings and token counts to the answer; `client.py` prints neither.

## What `make load USERS=10 SECONDS=60` counts

`USERS` concurrent clients, each sending one streamed chat completion after another for `SECONDS` seconds; a request already started is read to its end, and a client whose request failed waits a second before its next. Every request ends one of three ways:

- **answered:** HTTP 200 and a finished stream;
- **failed:** no answer reached the client: an HTTP status other than 200, a refused or reset connection, or a timeout or the end of the stream before the first token;
- **cut mid-answer:** the stream had sent tokens, then ended unfinished. The client holds part of an answer, which cannot be sent again without repeating it, so it is counted apart from the failures.

The report prints the three counts, the failures by what ended them, and `PASS` or `FAIL` for no failed request (the criterion every drill under load uses: zero failed client requests through the gateway), no stream cut mid-answer (with `CUT_OK=1` reported beside the count instead of judged) and at least one request answered, then the `== RESULT` line. `RECORDS=<file>` keeps one JSON line per request: its client, the second it started at, its status and how it ended. Nothing here measures how fast: neither the report nor the records hold a duration, a token count or a rate.

In the labs `load.py` runs on the operator's client (`sfab/client`, through `docker exec -i`), and the recipe's hostname is pinned to the internal Gateway's VIP (`SERVING_LOAD_RESOLVE`): the operator's public resolver, `ops-dns` where the lab holds it, publishes no platform name in build A's one-tenant state, so the render pins the name whenever the view that answers the client does not hold it. The request crosses the operator's IPsec tunnel into the firewall's `operator-vpn` zone and on to the internal Gateway: the network is inside what it counts. `--url` aims it at any other base URL.

## The images

| Image | Built by | What it holds |
|---|---|---|
| `sfab/serving:b11382-2` | `make -C images serving` (`image/`) | Debian 12 slim by digest; libgomp1 and libssl3 from their pinned packages; llama.cpp release b11382's `llama-server` and `ggml-rpc-server` with the libraries beside them; `sfab-ready`; an empty `/models`, where the recipe mounts the weights. No model: the two models are 14.5 GB and 16.5 GB files. Its user is 65532 |
| `sfab/keys:1` | `make -C images keys` (`images/keys/`) | `sfab-keys` on `sfab/client`, with PyYAML from its pinned wheel |

Every input is pinned in `spec/versions.yaml` with its sha256 (`images/README.md` lists where each comes from), and `make -C images registry-seed` pushes both images into the in-lab registry, from which the nodes pull them as `<mirror>/<repository>:<tag>`.

## The models

The labs serve two models (`spec/versions.yaml` `serving.models`, each pinned by Hugging Face repository, revision, file, sha256 and size):

| Model | The book's name | File | Size | License |
|---|---|---|---|---|
| Liquid AI LFM2.5-24B-A2B, a mixture of experts with about 2B parameters active per token (GGUF architecture `lfm2moe`) | `chat` | `LFM2.5-24B-A2B-Q4_K_M.gguf` | 14,526,258,464 bytes | LFM Open License v1.0 (its commercial-use grant stops at USD 10 million annual revenue) |
| Qwen3.8-27B, dense, 64 layers of which 16 full attention (GGUF architecture `qwen35`), as Unsloth's GGUF since Qwen publishes none | `staff` | `Qwen3.8-27B-UD-Q4_K_M.gguf` | 16,464,440,224 bytes | Apache-2.0 |

`make -C images models-fetch` puts both in `images/models/`, which git ignores (with `SFAB_MODELS_STORE=<dir>` they live in `<dir>`, and `images/models` is a link to it; `make -C images models-link` puts the link back after a sync), each checked against its sha256. A lab with serving on binds `images/models` read-only into each GPU node that runs a server, the node's launcher exports it to the guest over virtio-9p, the guest mounts it at `/srv/models` before kubelet starts (`images/vm-node/vm-init.sh`), and the recipe's PersistentVolume of that node mounts it in each server at `/models`. Preflight checks each file is there at its pinned size.

Both load in llama.cpp b11382, alone and through `ggml-rpc-server` (checked on the lab host, 2026-10-28). The servers run with `--reasoning-budget 0`, so an answer holds no reasoning, and with `--cache-ram 0 --ctx-checkpoints 0`, so a server keeps no prompt cache or context checkpoints in its memory.

## Metrics

Chapter 20 adds them: `llama-server --metrics` and a Prometheus scrape that carries the key, since at b11382 only `/health` and `/v1/health` answer without it. Until then the recipe exports none.

## Limits

The models run on CPU, each copy's layers on its RPC workers. Anything it measures is this lab's, not a GPU's. In production each of these copies fits one GPU (an NVIDIA B300 holds 288 GB; the BF16 weights are about 48 GB and 54 GB), so it is node-local and puts no traffic on the rails; the rails carry models larger than a node, disaggregated prefill and decode, and training. The lab's in-node RPC through the macvlan bridge stands in for a GPU's own memory, and its one spanning copy for a model larger than a node.
