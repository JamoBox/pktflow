//! File & mail transfer (11.9): the app-stream pattern proven for
//! `ftp`/`smtp`/`imap`/`pop3`, FTP's D15 no-data-channel criterion, TFTP's
//! D15 gate proven end to end, SMB2's session-id stream, and NFSv3/v4
//! fixtures.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use pktflow_core::{LinkType, PacketMeta, ParseOpts, RouteId, StopReason};
use pktflow_flows::{Aggregator, AggregatorConfig, Rollup};
use pktflow_plugins::default_engine;
use pktflow_plugins::ipv4::internet_checksum;

fn meta(len: usize, ms: u64) -> PacketMeta {
    PacketMeta {
        timestamp: SystemTime::UNIX_EPOCH + Duration::from_millis(ms),
        caplen: len,
        origlen: len,
        link_type: LinkType::ETHERNET,
    }
}

fn eth() -> Vec<u8> {
    let mut f = vec![0xAA; 6];
    f.extend_from_slice(&[0xBB; 6]);
    f.extend_from_slice(&0x0800u16.to_be_bytes());
    f
}

fn ipv4_tcp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let total = 20 + 20 + payload.len();
    let mut h = vec![
        0x45,
        0x00,
        (total >> 8) as u8,
        (total & 0xff) as u8,
        0x1C,
        0x46,
        0x40,
        0x00,
        0x40,
        6,
        0,
        0,
    ];
    h.extend_from_slice(&src);
    h.extend_from_slice(&dst);
    let ck = internet_checksum(&h);
    h[10..12].copy_from_slice(&ck.to_be_bytes());
    let mut seg = Vec::new();
    seg.extend_from_slice(&sport.to_be_bytes());
    seg.extend_from_slice(&dport.to_be_bytes());
    seg.extend_from_slice(&[0, 0, 1, 0, 0, 0, 0, 0]);
    seg.extend_from_slice(&[0x50, 0x18]);
    seg.extend_from_slice(&[0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00]);
    seg.extend_from_slice(payload);
    h.extend_from_slice(&seg);
    h
}

fn ipv4_udp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut h = vec![
        0x45, 0x00, 0x00, 0x3C, 0x1C, 0x46, 0x40, 0x00, 0x40, 17, 0, 0,
    ];
    h.extend_from_slice(&src);
    h.extend_from_slice(&dst);
    let ck = internet_checksum(&h);
    h[10..12].copy_from_slice(&ck.to_be_bytes());
    h.extend_from_slice(&sport.to_be_bytes());
    h.extend_from_slice(&dport.to_be_bytes());
    h.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    h.extend_from_slice(&[0, 0]);
    h.extend_from_slice(payload);
    h
}

// --- FTP (RFC 959) ------------------------------------------------------

#[test]
fn ftp_login_sequence_forms_one_app_stream_with_command_and_reply_rollups() {
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    let lines: [(bool, &[u8]); 4] = [
        (false, b"220 Welcome\r\n"),
        (true, b"USER anonymous\r\n"),
        (false, b"331 Please specify password\r\n"),
        (true, b"PASS guest@\r\n"),
    ];
    for (i, (from_client, line)) in lines.iter().enumerate() {
        let mut f = eth();
        if *from_client {
            f.extend_from_slice(&ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 50000, 21, line));
        } else {
            f.extend_from_slice(&ipv4_tcp([10, 0, 0, 2], [10, 0, 0, 1], 21, 50000, line));
        }
        agg.ingest(&engine.dissect(&f, meta(f.len(), i as u64), ParseOpts::default()));
    }

    let ftp_streams = agg.at_layer("ftp");
    assert_eq!(ftp_streams.len(), 1, "one app-stream per TCP session");
    match ftp_streams[0].rollups.get("command") {
        Some(Rollup::Accumulate { values, .. }) => {
            assert!(values
                .iter()
                .any(|v| *v == pktflow_core::Value::from("USER")));
            assert!(values
                .iter()
                .any(|v| *v == pktflow_core::Value::from("PASS")));
        }
        other => panic!("wrong rollup: {other:?}"),
    }
    match ftp_streams[0].rollups.get("reply_code") {
        Some(Rollup::Accumulate { values, .. }) => {
            assert!(values.contains(&pktflow_core::Value::U64(220)));
            assert!(values.contains(&pktflow_core::Value::U64(331)));
        }
        other => panic!("wrong rollup: {other:?}"),
    }
}

#[test]
fn ftp_pasv_response_exposes_port_in_arg_with_no_fabricated_data_stream() {
    // D15 criterion, tested not just stated: the negotiated data-channel
    // port is visible as raw text, but no data-channel stream is created.
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    let pasv_reply = b"227 Entering Passive Mode (10,0,0,2,200,3).\r\n";
    let mut f = eth();
    f.extend_from_slice(&ipv4_tcp(
        [10, 0, 0, 2],
        [10, 0, 0, 1],
        21,
        50000,
        pasv_reply,
    ));
    agg.ingest(&engine.dissect(&f, meta(f.len(), 0), ParseOpts::default()));

    let ftp_streams = agg.at_layer("ftp");
    assert_eq!(ftp_streams.len(), 1);
    // Only one TCP stream exists (the control channel) — no phantom data
    // channel was fabricated from the PASV reply's port numbers.
    assert_eq!(agg.at_layer("tcp").len(), 1);
}

// --- TFTP (RFC 1350, D15) ------------------------------------------------

#[test]
fn tftp_rrq_reaches_the_dissector_but_continuation_stops_at_unclaimed_ephemeral_port() {
    let engine = Arc::new(default_engine());

    // RRQ to the well-known port 69: reachable via the static claim.
    let mut rrq_payload = 1u16.to_be_bytes().to_vec();
    rrq_payload.extend_from_slice(b"boot.img\0octet\0");
    let mut rrq_frame = eth();
    rrq_frame.extend_from_slice(&ipv4_udp(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        50000,
        69,
        &rrq_payload,
    ));
    let packet = engine.dissect(&rrq_frame, meta(rrq_frame.len(), 0), ParseOpts::default());
    let protocols: Vec<_> = packet.layers.iter().map(|l| l.protocol).collect();
    assert_eq!(protocols, ["ethernet", "ipv4", "udp", "tftp"]);

    // The server's DATA reply comes from an ephemeral port on both sides —
    // D15's gate stops it at UDP with UnclaimedRoute, not silently
    // vanishing or misparsing (the acceptance criterion, verified
    // end-to-end rather than only asserted in prose).
    let mut data_payload = 3u16.to_be_bytes().to_vec();
    data_payload.extend_from_slice(&1u16.to_be_bytes());
    data_payload.extend_from_slice(&[0xAB; 512]);
    let mut data_frame = eth();
    data_frame.extend_from_slice(&ipv4_udp(
        [10, 0, 0, 2],
        [10, 0, 0, 1],
        55000,
        50001,
        &data_payload,
    ));
    let packet = engine.dissect(&data_frame, meta(data_frame.len(), 1), ParseOpts::default());
    let protocols: Vec<_> = packet.layers.iter().map(|l| l.protocol).collect();
    assert_eq!(protocols, ["ethernet", "ipv4", "udp"]);
    assert_eq!(
        packet.stop,
        StopReason::UnclaimedRoute(RouteId::UdpPort(50001))
    );
}

// --- SMTP/IMAP/POP3 app-stream folding ----------------------------------

#[test]
fn smtp_ehlo_mail_rcpt_data_sequence_folds_into_one_app_stream() {
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    let lines: [(bool, &[u8]); 5] = [
        (false, b"220 mail.example.com ESMTP\r\n"),
        (true, b"EHLO client.example.com\r\n"),
        (false, b"250 mail.example.com\r\n"),
        (true, b"MAIL FROM:<a@example.com>\r\n"),
        (true, b"RCPT TO:<b@example.com>\r\n"),
    ];
    for (i, (from_client, line)) in lines.iter().enumerate() {
        let mut f = eth();
        if *from_client {
            f.extend_from_slice(&ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 50000, 25, line));
        } else {
            f.extend_from_slice(&ipv4_tcp([10, 0, 0, 2], [10, 0, 0, 1], 25, 50000, line));
        }
        agg.ingest(&engine.dissect(&f, meta(f.len(), i as u64), ParseOpts::default()));
    }

    let smtp_streams = agg.at_layer("smtp");
    assert_eq!(smtp_streams.len(), 1, "one app-stream per TCP session");
    match smtp_streams[0].rollups.get("command") {
        Some(Rollup::Accumulate { values, .. }) => {
            assert!(values
                .iter()
                .any(|v| *v == pktflow_core::Value::from("EHLO")));
            assert!(values
                .iter()
                .any(|v| *v == pktflow_core::Value::from("MAIL")));
            assert!(values
                .iter()
                .any(|v| *v == pktflow_core::Value::from("RCPT")));
        }
        other => panic!("wrong rollup: {other:?}"),
    }
}

#[test]
fn imap_login_select_fetch_sequence_accumulates_commands() {
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    let lines: [(bool, &[u8]); 4] = [
        (true, b"A001 LOGIN alice password\r\n"),
        (false, b"A001 OK LOGIN completed\r\n"),
        (true, b"A002 SELECT INBOX\r\n"),
        (true, b"A003 FETCH 1 BODY[]\r\n"),
    ];
    for (i, (from_client, line)) in lines.iter().enumerate() {
        let mut f = eth();
        if *from_client {
            f.extend_from_slice(&ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 50000, 143, line));
        } else {
            f.extend_from_slice(&ipv4_tcp([10, 0, 0, 2], [10, 0, 0, 1], 143, 50000, line));
        }
        agg.ingest(&engine.dissect(&f, meta(f.len(), i as u64), ParseOpts::default()));
    }

    let imap_streams = agg.at_layer("imap");
    assert_eq!(imap_streams.len(), 1);
    match imap_streams[0].rollups.get("command") {
        Some(Rollup::Accumulate { values, .. }) => {
            assert!(values
                .iter()
                .any(|v| *v == pktflow_core::Value::from("LOGIN")));
            assert!(values
                .iter()
                .any(|v| *v == pktflow_core::Value::from("SELECT")));
            assert!(values
                .iter()
                .any(|v| *v == pktflow_core::Value::from("FETCH")));
        }
        other => panic!("wrong rollup: {other:?}"),
    }
}

#[test]
fn pop3_user_pass_stat_retr_sequence_accumulates_commands() {
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    let lines: [(bool, &[u8]); 4] = [
        (true, b"USER alice\r\n"),
        (true, b"PASS secret\r\n"),
        (true, b"STAT\r\n"),
        (true, b"RETR 1\r\n"),
    ];
    for (i, (from_client, line)) in lines.iter().enumerate() {
        let mut f = eth();
        if *from_client {
            f.extend_from_slice(&ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 50000, 110, line));
        } else {
            f.extend_from_slice(&ipv4_tcp([10, 0, 0, 2], [10, 0, 0, 1], 110, 50000, line));
        }
        agg.ingest(&engine.dissect(&f, meta(f.len(), i as u64), ParseOpts::default()));
    }

    let pop3_streams = agg.at_layer("pop3");
    assert_eq!(pop3_streams.len(), 1);
    match pop3_streams[0].rollups.get("command") {
        Some(Rollup::Accumulate { values, count, .. }) => {
            assert_eq!(*count, 4);
            assert!(values
                .iter()
                .any(|v| *v == pktflow_core::Value::from("STAT")));
            assert!(values
                .iter()
                .any(|v| *v == pktflow_core::Value::from("RETR")));
        }
        other => panic!("wrong rollup: {other:?}"),
    }
}

// --- SMB2 (MS-SMB2) -------------------------------------------------------

fn smb2_message(
    command: u16,
    flags: u32,
    message_id: u64,
    tree_id: u32,
    session_id: u64,
) -> Vec<u8> {
    let mut h = vec![0xFEu8, b'S', b'M', b'B'];
    h.extend_from_slice(&64u16.to_be_bytes());
    h.extend_from_slice(&0u16.to_be_bytes());
    h.extend_from_slice(&0u32.to_be_bytes());
    h.extend_from_slice(&command.to_be_bytes());
    h.extend_from_slice(&0u16.to_be_bytes());
    h.extend_from_slice(&flags.to_be_bytes());
    h.extend_from_slice(&0u32.to_be_bytes());
    h.extend_from_slice(&message_id.to_be_bytes());
    h.extend_from_slice(&0u32.to_be_bytes());
    h.extend_from_slice(&tree_id.to_be_bytes());
    h.extend_from_slice(&session_id.to_be_bytes());
    h.extend_from_slice(&[0u8; 16]);
    let mut msg = vec![0x00];
    msg.extend_from_slice(&(h.len() as u32).to_be_bytes()[1..]);
    msg.extend_from_slice(&h);
    msg
}

#[test]
fn smb2_operation_sequence_forms_one_session_id_stream() {
    const NEGOTIATE: u16 = 0;
    const SESSION_SETUP: u16 = 1;
    const TREE_CONNECT: u16 = 3;
    const CREATE: u16 = 5;
    const READ: u16 = 8;
    const CLOSE: u16 = 6;
    const SERVER_TO_REDIR: u32 = 0x0000_0001;

    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    // Negotiate/SessionSetup happen before a session_id is assigned (0);
    // once assigned, the rest of the exchange uses it consistently.
    let steps: [(u16, u32, u64, u32, u64); 6] = [
        (NEGOTIATE, 0, 1, 0, 0),
        (SESSION_SETUP, SERVER_TO_REDIR, 2, 0, 0xCAFE),
        (TREE_CONNECT, 0, 3, 7, 0xCAFE),
        (CREATE, 0, 4, 7, 0xCAFE),
        (READ, 0, 5, 7, 0xCAFE),
        (CLOSE, 0, 6, 7, 0xCAFE),
    ];
    for (i, (command, flags, message_id, tree_id, session_id)) in steps.iter().enumerate() {
        let payload = smb2_message(*command, *flags, *message_id, *tree_id, *session_id);
        let mut f = eth();
        f.extend_from_slice(&ipv4_tcp(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            50000,
            445,
            &payload,
        ));
        agg.ingest(&engine.dissect(&f, meta(f.len(), i as u64), ParseOpts::default()));
    }

    let smb2_streams = agg.at_layer("smb2");
    // Two session-id streams: 0 (Negotiate, pre-auth) and 0xCAFE (everything
    // after SessionSetup) — both real, keyed correctly by session_id.
    assert_eq!(smb2_streams.len(), 2, "one stream per distinct session_id");

    let cafe_stream = smb2_streams
        .iter()
        .find(|s| {
            matches!(
                s.key_fields.get("session_id"),
                Some(pktflow_core::Value::U64(0xCAFE))
            )
        })
        .expect("session 0xCAFE stream exists");
    match cafe_stream.rollups.get("command") {
        Some(Rollup::Accumulate { values, count, .. }) => {
            assert_eq!(*count, 5);
            assert!(values.contains(&pktflow_core::Value::U64(u64::from(CREATE))));
            assert!(values.contains(&pktflow_core::Value::U64(u64::from(READ))));
            assert!(values.contains(&pktflow_core::Value::U64(u64::from(CLOSE))));
        }
        other => panic!("wrong rollup: {other:?}"),
    }
}

// --- NFS (RFC 1813 / RFC 7530) --------------------------------------------

#[test]
fn nfsv3_getattr_call_and_reply_pair_parse_their_envelope_fields() {
    let engine = Arc::new(default_engine());

    let mut call = 0x1111_1111u32.to_be_bytes().to_vec();
    call.extend_from_slice(&0u32.to_be_bytes()); // CALL
    call.extend_from_slice(&2u32.to_be_bytes()); // rpcvers
    call.extend_from_slice(&100_003u32.to_be_bytes()); // program
    call.extend_from_slice(&3u32.to_be_bytes()); // v3
    call.extend_from_slice(&1u32.to_be_bytes()); // GETATTR
    let mut call_frame = eth();
    call_frame.extend_from_slice(&ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 700, 2049, &call));
    let packet = engine.dissect(&call_frame, meta(call_frame.len(), 0), ParseOpts::default());
    let layer = packet.layers.last().expect("nfs layer");
    assert_eq!(layer.protocol, "nfs");
    assert_eq!(
        layer.fields.get("procedure"),
        Some(&pktflow_core::Value::U64(1))
    );

    let mut reply = 0x1111_1111u32.to_be_bytes().to_vec();
    reply.extend_from_slice(&1u32.to_be_bytes()); // REPLY
    reply.extend_from_slice(&0u32.to_be_bytes()); // MSG_ACCEPTED
    let mut reply_frame = eth();
    reply_frame.extend_from_slice(&ipv4_udp([10, 0, 0, 2], [10, 0, 0, 1], 2049, 700, &reply));
    let packet = engine.dissect(
        &reply_frame,
        meta(reply_frame.len(), 1),
        ParseOpts::default(),
    );
    let layer = packet.layers.last().expect("nfs layer");
    assert_eq!(layer.protocol, "nfs");
    assert_eq!(
        layer.fields.get("msg_type"),
        Some(&pktflow_core::Value::from("reply"))
    );
}

#[test]
fn nfsv4_compound_call_parses_with_procedure_one_and_no_op_list_walk() {
    let engine = Arc::new(default_engine());
    let mut call = 0x2222_2222u32.to_be_bytes().to_vec();
    call.extend_from_slice(&0u32.to_be_bytes()); // CALL
    call.extend_from_slice(&2u32.to_be_bytes());
    call.extend_from_slice(&100_003u32.to_be_bytes());
    call.extend_from_slice(&4u32.to_be_bytes()); // v4
    call.extend_from_slice(&1u32.to_be_bytes()); // COMPOUND
                                                 // Opaque cred/verf + a fake operation list this plugin never walks.
    call.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x01]);

    let mut frame = eth();
    frame.extend_from_slice(&ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 700, 2049, &call));
    let packet = engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default());
    let layer = packet.layers.last().expect("nfs layer");
    assert_eq!(layer.protocol, "nfs");
    assert_eq!(
        layer.fields.get("program_version"),
        Some(&pktflow_core::Value::U64(4))
    );
    assert_eq!(
        layer.fields.get("procedure"),
        Some(&pktflow_core::Value::U64(1))
    );
    // header_len stops right after the fixed envelope — the opaque
    // cred/verf and operation list are unparsed remainder, not walked.
    assert_eq!(layer.header_len, 24);
}
