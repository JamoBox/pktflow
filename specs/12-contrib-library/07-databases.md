# 12.7 — Databases & datastores: MySQL, PostgreSQL, TDS, MongoDB

> Task: [12 Contrib library](README.md) · Depends on: 02–06 · PRD: FR-32 · D7, D12, D14, D16

## Goal
The four client/server database wire protocols that dominate real application traffic.
Depth is capped at "who connected to which database and what *kind* of operation is this" —
command/message types and connection metadata, never query text or row data (D7: a SQL
string is payload content, exactly as 11.14 capped `amqp` at class/method and `redis` at
the command name).

## Specification

**mysql** (MySQL Client/Server Protocol — Oracle's *MySQL Internals* manual / MariaDB
protocol docs; *no standards body*, the project documentation is canonical).

| Item | Spec |
|---|---|
| Claims | `TcpPort(3306)` |
| Fields | `Keys`: `app` (shared, constant `Str("mysql")`) · `Structural`: `packet_len` (3-byte LE), `sequence_id` · `Full`: server greeting → `protocol_version` (10), `server_version` (Str, the null-terminated banner — fingerprints MySQL vs MariaDB vs proxies), `capability_flags`; client command packet (sequence_id 0) → `command` (Str: COM_QUERY 0x03/COM_QUIT 0x01/COM_INIT_DB 0x02/COM_PING 0x0E/COM_STMT_PREPARE 0x16/COM_STMT_EXECUTE 0x17/...) |
| Hint | `Terminal` — COM_QUERY's statement text is not extracted (D7); TLS after a client capability upgrade is the D12 boundary |
| Identity | key `[{app, None}]`, one child per TCP session |
| Rollups | `Accumulate` on `command`; `Sample` on `server_version` |

**pgsql** (PostgreSQL Frontend/Backend Protocol v3 — postgresql.org documentation;
*no standards body*).

| Item | Spec |
|---|---|
| Claims | `TcpPort(5432)` |
| Fields | `Keys`: `app` (shared, constant `Str("pgsql")`) · `Structural`: `msg_type` (Str — frontend `Q` Query/`P` Parse/`B` Bind/`E` Execute/`X` Terminate, backend `R` Authentication/`T` RowDescription/`D` DataRow/`C` CommandComplete/`Z` ReadyForQuery, or the untyped `Startup`/`SSLRequest`), `length` · `Full` (startup message only — protocol `0x00030000`): `user` (Str), `database` (Str), `application_name` (Str) — the same connection-attribution value as 11.7 `ldap`'s `bind_dn` |
| Hint | `Terminal`; an `SSLRequest` (code 80877103) marks the D12 upgrade boundary |
| Identity | key `[{app, None}]`, one child per TCP session |
| Rollups | `Accumulate` on `msg_type`; `Sample` on `user`, `database` |

**tds** (*no open standard* — Microsoft [MS-TDS] Open Specification; SQL Server).

| Item | Spec |
|---|---|
| Claims | `TcpPort(1433)` |
| Fields | `Keys`: `app` (shared, constant `Str("tds")`) · `Structural`: `packet_type` (0x01 SQL Batch/0x03 RPC/0x04 Tabular Result/0x10 TDS7 Login/0x12 Prelogin/...), `status`, `length`, `spid` · `Full` (PRELOGIN token walk only): `version`, `encryption` (0 off/1 on/2 not-supported/3 required) |
| Hint | `Terminal` — modern deployments negotiate encryption at prelogin (D12); LOGIN7 and batch content past that boundary are opaque, and even cleartext batches yield only `packet_type` (D7) |
| Identity | key `[{app, None}]`, one child per TCP session |
| Rollups | `Accumulate` on `packet_type`; `Sample` on `encryption` |

**mongodb** (MongoDB Wire Protocol — mongodb.com documentation; *no standards body*).

| Item | Spec |
|---|---|
| Claims | `TcpPort(27017)` |
| Fields | `Keys`: `app` (shared, constant `Str("mongodb")`) · `Structural`: `message_length`, `request_id`, `response_to`, `opcode` (2013 OP_MSG/2012 OP_COMPRESSED/2004 OP_QUERY legacy/1 OP_REPLY legacy) · `Full` (OP_MSG, section kind 0): `command` (Str — the first BSON element key of the body document: `find`/`insert`/`update`/`hello`/`isMaster`/..., a bounded read of one key, never a document walk — `redis`'s command-name stance, 11.14) |
| Hint | `Terminal` |
| Identity | key `[{app, None}]`, one child per TCP session |
| Rollups | `Accumulate` on `command`; `Accumulate` on `opcode` |

### Planned (Tier 2 — not yet specified)
| Protocol | Standard | Note |
|---|---|---|
| Oracle TNS | *Proprietary* (Oracle) — no public spec; reverse-engineered docs are the closest source | `TcpPort(1521)`; connect-string metadata is the prize |
| ClickHouse native | *Project doc* — ClickHouse native protocol docs | `TcpPort(9000)` |
| ZooKeeper | *Project doc* — Apache ZooKeeper jute protocol | `TcpPort(2181)`; coordination traffic, four-letter admin words |
| Couchbase | *Project doc* — memcached binary protocol derivative | `TcpPort(11210)`; taxonomy-adjacent to 11.14's Tier-2 Memcached, kept distinct deliberately |
| InfluxDB line protocol | *Project doc* | UDP writes only (the HTTP API is 11.8's territory) |

## Acceptance criteria
- [ ] `mysql` fixture: server greeting + login + COM_QUERY + COM_QUIT sequence parses
      exactly; the query's SQL text is verifiably absent from every extracted field (the
      D7 cap tested, not stated).
- [ ] `pgsql` fixture: startup (user/database extracted) + simple-query round trip parses
      exactly; an SSLRequest fixture stops at the D12 boundary with `msg_type` only.
- [ ] `tds` fixture: PRELOGIN request/response (encryption token decoded) + login sequence
      parses exactly; post-negotiation TLS bytes decline rather than misparse.
- [ ] `mongodb` fixture: OP_MSG `hello` + `find` + reply parse `command`/`opcode` exactly;
      an OP_COMPRESSED message yields envelope fields only (no decompression attempt —
      explicit non-goal, tested).
- [ ] All four app-stream children form correctly under their TCP sessions (06.6 pattern).
