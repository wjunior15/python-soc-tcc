DROP TABLE IF EXISTS alerts, captures;

CREATE TABLE captures(
    id_pcap SERIAL,
    ip_src varchar(50) NOT NULL,
    ip_dst varchar(50) NOT NULL,
    timestamp_conn bigint NOT NULL,
    src_port varchar(10),
    dst_port varchar(10),
    syn_flag integer NOT NULL,
    ack_flag integer NOT NULL,
    win_size decimal(8),
    cap_status varchar(50),
    CONSTRAINT PK_pcap PRIMARY KEY (id_pcap)
);

CREATE TABLE alerts(
    id_alert SERIAL,
    id_pcap integer,
    label varchar(50) NOT NULL,
    init_win_fwd integer,
    ack_count integer,
    fwd_pck decimal(8),
    flw_pck decimal(8),
    iat_max decimal(8),
    iat_min decimal(8),
    flw_duration decimal(8),
    init_win_bwd integer,
    sub_bwd decimal(8),
    iat_mean decimal(8),
    CONSTRAINT PK_alert PRIMARY KEY (id_alert, id_pcap),
    CONSTRAINT FK_alert_pcap FOREIGN KEY (id_pcap) REFERENCES captures(id_pcap)
);