# 11.14 — Data-center & application messaging: MQTT, AMQP 0-9-1, Redis (RESP)

> Task: [11 Standard library](README.md) · Depends on: 02–06 · PRD: FR-31 · D7, D13, D14

## Goal
The message-broker and cache/datastore wire protocols that dominate DC and IoT/telemetry
traffic. All three follow the app-stream pattern (06.6); depth is deliberately capped at
"what kind of operation is this" rather than fully decoding every argument, matching this
task's established honesty stance for TLV/frame-envelope protocols (LDAP's `bind_dn`,
EtherNet/IP's `cip_service`, 11.7/11.13).

## Specification

**mqtt** (OASIS MQTT Version 5.0, also ISO/IEC 20922).

| Item | Spec |
|---|---|
| Claims | `TcpPort(1883)` |
| Fields | `Keys`: `app` (shared, constant `Str("mqtt")`) · `Structural`: `message_type` (CONNECT/CONNACK/PUBLISH/PUBACK/SUBSCRIBE/SUBACK/PINGREQ/DISCONNECT/...), `remaining_length` (the variable-length-encoded field, 1–4 bytes, continuation-bit scheme) · `Full`: CONNECT → `client_id` (Str), `keep_alive`; PUBLISH → `topic` (Str), `qos` (U64, from header flags), `retain` (Bool); SUBSCRIBE → `topics` (List of Str) |
| Hint | `Terminal` |
| Identity | key `[{app, None}]`, one `mqtt` child stream per TCP session |
| Rollups | `Accumulate` on `message_type`; `Accumulate` on `topic` (the PUBLISH topics observed — the same PRD §4.A "query names observed" pattern `dns` demonstrates, 06.6, applied to pub/sub topics) |

**amqp** (AMQP 0-9-1 — the RabbitMQ-maintained specification; **distinct** from AMQP **1.0**,
which is the separate OASIS/ISO 19464 standard and a different wire format entirely).

| Item | Spec |
|---|---|
| Claims | `TcpPort(5672)` |
| Fields | `Keys`: `app` (shared, constant `Str("amqp")`) · `Structural`: `frame_type` (Method=1/Header=2/Body=3/Heartbeat=8), `channel` (U64), `size` · `Full` (Method frames only): `class_id`, `method_id` (identify *what kind* of AMQP operation this is — e.g. class 60/method 40 is `Basic.Publish` — without decoding that method's argument list, which varies per method and is out of v1 scope) |
| Hint | `Terminal` |
| Identity | key `[{app, None}]`, one `amqp` child stream per TCP session |
| Rollups | `Accumulate` on `frame_type`; `Accumulate` on `class_id` |

**redis** (RESP — Redis Serialization Protocol, redis.io; *no standards body*, the project's
own documentation is the canonical reference).

| Item | Spec |
|---|---|
| Claims | `TcpPort(6379)` |
| Fields | `Keys`: `app` (shared, constant `Str("redis")`) · `Structural`: `resp_type` (Simple String `+`/Error `-`/Integer `:`/Bulk String `$`/Array `*`) · `Full`: `command` (Str, the first bulk-string element of a client-direction RESP array — `GET`/`SET`/`DEL`/...), `arg_count` (U64, the array's declared element count) |
| Hint | `Terminal` — only enough of the array is walked to read the command name; deeper argument values are not decoded (the same bounded-depth stance as `amqp`'s method arguments) |
| Identity | key `[{app, None}]`, one `redis` child stream per TCP session |
| Rollups | `Accumulate` on `command` |

### Planned (Tier 2 — not yet specified)
| Protocol | Standard | Note |
|---|---|---|
| Kafka wire protocol | *Project doc* — Apache Kafka protocol guide | |
| Memcached | *Project doc* — `protocol.txt` in memcached source | Both text and binary variants |
| Cassandra/CQL | *Project doc* — Apache Cassandra native protocol spec | |

## Acceptance criteria
- [ ] `mqtt` fixture covers CONNECT/CONNACK/PUBLISH/SUBSCRIBE; `remaining_length`'s
      variable-length continuation-bit encoding tested at the 1-byte/2-byte boundary
      (127/128 and 16383/16384).
- [ ] `amqp` fixture: a Method frame (`Basic.Publish`) plus its following Header and Body
      frames on the same channel parse `frame_type`/`class_id`/`method_id` exactly; Body
      frame content itself is left as payload (not decoded).
- [ ] `redis` fixture: a `SET foo bar` command array and a simple-string `+OK` response parse
      `command`/`resp_type` exactly; a nested-array command (e.g. `MULTI`/`EXEC` pipeline)
      still yields the correct top-level `command` without attempting the nested walk.
- [ ] Each plugin's app-stream child stream forms correctly under its TCP session (06.6
      pattern verified for all three).
