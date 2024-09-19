CREATE TABLE captures(
    ip_src varchar(50) NOT NULL,
    ip_dst varchar(50) NOT NULL,
    timestamp_conn bigint NOT NULL,
    src_port varchar(10),
    dst_port varchar(10),
    syn_flag integer NOT NULL,
    ack_flag integer NOT NULL,
    win_size decimal(8),
    cap_status varchar(50),
    CONSTRAINT PK_pcap PRIMARY KEY (ip_src, ip_dst, timestamp_conn)
);

CREATE TABLE alerts(
    ip_src varchar(50) NOT NULL,
    ip_dst varchar(50) NOT NULL,
    timestamp_conn bigint NOT NULL,
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
    CONSTRAINT PK_alert PRIMARY KEY (ip_src, ip_dst, timestamp_conn, label),
    CONSTRAINT FK_alert_pcap FOREIGN KEY (ip_src, ip_dst, timestamp_conn) REFERENCES captures(ip_src, ip_dst, timestamp_conn)

);