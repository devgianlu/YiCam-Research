pppp_proto = Proto("pppp", "PPPP")

header_type_F = ProtoField.uint8("pppp.header.type", "Packet type", base.HEX)
header_size_F = ProtoField.uint16("pppp.header.size", "Packet size")

pppp_device_uid_F = ProtoField.string("pppp.device_uid", "Device UID")
pppp_api_version_F = ProtoField.string("pppp.api_version", "API version")

pppp_addr_family_F = ProtoField.uint16("pppp.addr.family", "Family")
pppp_addr_port_F = ProtoField.uint16("pppp.addr.port", "Port")
pppp_addr_ip_F = ProtoField.ipv4("pppp.addr.ip", "IP")

dev_login_key_nat_type_F = ProtoField.uint8("pppp.dev_login_key.nat_type", "NAT type")
dev_login_key_nonce_F = ProtoField.string("pppp.dev_login_key.nonce", "Nonce")
dev_login_key_signature_F = ProtoField.string("pppp.dev_login_key.signature", "Signature")

dev_login_key_ack_result_F = ProtoField.int8("pppp.dev_login_key_ack.result", "Result")
dev_login_key_ack_login_interval_F = ProtoField.uint8("pppp.dev_login_key_ack.login_interval", "Login interval")

punch_to_timestamp_F = ProtoField.uint32("pppp.punch_to.timestamp", "Timestamp")
punch_to_hash_F = ProtoField.bytes("pppp.punch_to.timestamp", "Hash")

punch_pkt_timestamp_F = ProtoField.uint32("pppp.punch_pkt.timestamp", "Timestamp")
punch_pkt_hash_F = ProtoField.bytes("pppp.punch_pkt.timestamp", "Hash")

rly_tcp_to_ticket_F = ProtoField.string("pppp.rly_tcp_to.ticket", "Ticket")
rly_tcp_to_hash_F = ProtoField.bytes("pppp.rly_tcp_to.hash", "Hash")
rly_tcp_to_is_device_F = ProtoField.int8("pppp.rly_tcp_to.is_device", "Is device")
rly_tcp_to_status_F = ProtoField.int8("pppp.rly_tcp_to.status", "Status")

rly_tcp_result_ticket_F = ProtoField.string("pppp.rly_tcp_result.ticket", "Ticket")
rly_tcp_result_status_F = ProtoField.int8("pppp.rly_tcp_result.status", "Status")

drw_channel_num_F = ProtoField.uint8("pppp.drw.channel", "Channel number")
drw_packet_index_F = ProtoField.uint16("pppp.drw.index", "Packet index")

drw_ack_channel_num_F = ProtoField.uint8("pppp.drw_ack.channel", "Channel number")
drw_ack_packet_index_F = ProtoField.uint16("pppp.drw_ack.index", "Packet index")
drw_ack_packet_count_F = ProtoField.uint16("pppp.drw_ack.count", "Packet count")

pppp_proto.fields = {
    header_magic_F, header_type_F, header_size_F,
    pppp_device_uid_F, pppp_api_version_F,
    pppp_addr_family_F, pppp_addr_port_F, pppp_addr_ip_F,
    dev_login_key_nat_type_F, dev_login_key_nonce_F, dev_login_key_signature_F,
    dev_login_key_ack_result_F, dev_login_key_ack_login_interval_F,
    punch_to_timestamp_F, punch_to_hash_F,
    punch_pkt_timestamp_F, punch_pkt_hash_F,
    rly_tcp_to_ticket_F, rly_tcp_to_hash_F, rly_tcp_to_is_device_F, rly_tcp_to_status_F,
    rly_tcp_result_ticket_F, rly_tcp_result_status_F,
    drw_channel_num_F, drw_packet_index_F,
    drw_ack_channel_num_F, drw_ack_packet_index_F, drw_ack_packet_count_F
}

pppp_ensure_E = ProtoExpert.new('pppp.errors.ensure', 'Ensure bytes failed', PI_MALFORMED, PI_ERROR)
pppp_unknown_E = ProtoExpert.new('pppp.errors.unknown', 'Unknown packet', PI_MALFORMED, PI_ERROR)

pppp_proto.experts = { pppp_ensure_E, pppp_unknown_E }

function heuristic_checker(buf, pinfo, tree)
    if buf:len() < 4 then
        return false
    end
    if buf(0, 1):uint() ~= 0xf1 then
        return false
    end
    pppp_proto.dissector(buf, pinfo, tree)
    return true
end

function ensure_equal(buf, arr, tree)
    if buf:len() ~= arr:len() then
        tree:add_tvb_expert_info(pppp_ensure_E, buf, 'Different length')
        return
    end

    local raw = buf:bytes()
    for i = 0, raw:len() - 1 do
        if raw:get_index(i) ~= arr:get_index(i) then
            tree:add_tvb_expert_info(pppp_ensure_E, buf, 'Different bytes')
            return
        end
    end
end

function ensure_zero(buf, tree)
    local raw = buf:bytes()
    for i = 0, raw:len() - 1 do
        if raw:get_index(i) ~= 0 then
            tree:add_tvb_expert_info(pppp_ensure_E, buf, 'Not zero')
            return
        end
    end
end

function parse_device_uid(buf, tree)
    local prefix = buf(0, 8):stringz()
    local serial = buf(8, 4):uint()
    local check_code = buf(12, 8):string()
    tree:add(pppp_device_uid_F, buf, prefix .. '-' .. tostring(serial) .. '-' .. check_code)
end

function parse_api_version(buf, tree)
    local major = buf(0, 1):uint()
    local minor = buf(1, 1):uint()
    local patch = buf(2, 1):uint()
    tree:add(pppp_api_version_F, buf, tostring(major) .. '.' .. tostring(minor) .. '.' .. tostring(patch))
end

function parse_network_addr_le(buf, tree, name)
    local subtree = tree:add(pppp_proto, buf, name)
    subtree:add(pppp_addr_family_F, buf(0, 2))
    subtree:add_le(pppp_addr_port_F, buf(2, 2))
    subtree:add_le(pppp_addr_ip_F, buf(4, 4))
    ensure_zero(buf(8, 8), subtree)
end

function parse_network_addr_be(buf, tree, name)
    local subtree = tree:add(pppp_proto, buf, name)
    subtree:add_le(pppp_addr_family_F, buf(0, 2))
    subtree:add(pppp_addr_port_F, buf(2, 2))
    subtree:add(pppp_addr_ip_F, buf(4, 4))
    ensure_zero(buf(8, 8), subtree)
end

function pppp_hello(buf, _, tree)
    if buf:len() > 0 then
        tree:add_expert_info(PI_MALFORMED, PI_ERROR, 'invalid packet length: ' .. buf:len())
        return
    end

    return 'HELLO'
end

function pppp_hello_ack(buf, _, tree)
    if buf:len() ~= 16 then
        tree:add_expert_info(PI_MALFORMED, PI_ERROR, 'invalid packet length: ' .. buf:len())
        return
    end

    parse_network_addr_le(buf(0, 16), tree, 'WAN address')
    return 'HELLO_ACK'
end

function pppp_dev_login_key(buf, _, tree)
    if buf:len() ~= 104 then
        tree:add_expert_info(PI_MALFORMED, PI_ERROR, 'invalid packet length: ' .. buf:len())
        return
    end

    parse_device_uid(buf(0, 20), tree)
    tree:add(dev_login_key_nat_type_F, buf(20, 1))
    parse_api_version(buf(21, 3), tree)
    parse_network_addr_le(buf(24, 16), tree, 'Local address')
    tree:add(dev_login_key_nonce_F, buf(40, 32))
    tree:add(dev_login_key_signature_F, buf(72, 32))
    return 'DEV_LOGIN_KEY_EX'
end

function pppp_dev_login_key_ack(buf, _, tree)
    if buf:len() ~= 4 then
        tree:add_expert_info(PI_MALFORMED, PI_ERROR, 'invalid packet length: ' .. buf:len())
        return
    end

    tree:add(dev_login_key_ack_result_F, buf(0, 1))
    tree:add(dev_login_key_ack_login_interval_F, buf(1, 1))
    ensure_equal(buf(2, 2), ByteArray.new('0300'), tree)
    return 'DEV_LOGIN_KEY_ACK'
end

function pppp_punch_to(buf, _, tree)
    if buf:len() ~= 40 then
        tree:add_expert_info(PI_MALFORMED, PI_ERROR, 'invalid packet length: ' .. buf:len())
        return
    end

    parse_network_addr_le(buf(0, 16), tree, 'To address')
    ensure_equal(buf(16, 4), ByteArray.new('00000001'), tree)
    tree:add(punch_to_timestamp_F, buf(20, 4))
    tree:add(punch_to_hash_F, buf(24, 16))
    return 'PUNCH_TO_EX'
end

function pppp_punch_pkt(buf, _, tree)
    if buf:len() ~= 44 then
        tree:add_expert_info(PI_MALFORMED, PI_ERROR, 'invalid packet length: ' .. buf:len())
        return
    end

    parse_device_uid(buf(0, 20), tree)
    parse_api_version(buf(20, 3), tree)
    ensure_zero(buf(23, 1), tree)
    tree:add(punch_pkt_timestamp_F, buf(24, 4))
    tree:add(punch_pkt_hash_F, buf(28, 16))
    return 'PUNCH_PKT_EX'
end

function pppp_rly_tcp_to(buf, _, tree)
    if buf:len() == 48 then
        parse_network_addr_be(buf(0, 16), tree, 'Relay address')
        tree:add(rly_tcp_to_ticket_F, buf(16, 16))
        tree:add(rly_tcp_to_hash_F, buf(32, 16))
        return 'RLY_TCP_TO_EX'
    elseif buf:len() == 40 then
        parse_device_uid(buf(0, 20), tree)
        tree:add(rly_tcp_to_ticket_F, buf(20, 16))
        tree:add(rly_tcp_to_is_device_F, buf(36, 1))
        tree:add(rly_tcp_to_status_F, buf(37, 1))
        ensure_zero(buf(38, 2), tree)
        return 'RLY_TCP_TO_ACK'
    else
        tree:add_expert_info(PI_MALFORMED, PI_ERROR, 'invalid packet length: ' .. buf:len())
    end
end

function pppp_rly_tcp_result(buf, _, tree)
    if buf:len() ~= 20 then
        tree:add_expert_info(PI_MALFORMED, PI_ERROR, 'invalid packet length: ' .. buf:len())
        return
    end

    tree:add(rly_tcp_result_ticket_F, buf(0, 16))
    tree:add(rly_tcp_result_status_F, buf(16, 1))
    ensure_zero(buf(17, 3), tree)
    return 'RLY_TCP_RESULT'
end

function pppp_alive(buf, _, tree)
    if buf:len() ~= 0 then
        tree:add_expert_info(PI_MALFORMED, PI_ERROR, 'invalid packet length: ' .. buf:len())
        return
    end

    return 'ALIVE'
end

function pppp_alive_ack(buf, _, tree)
    if buf:len() ~= 0 then
        tree:add_expert_info(PI_MALFORMED, PI_ERROR, 'invalid packet length: ' .. buf:len())
        return
    end

    return 'ALIVE_ACK'
end

function pppp_drw(buf, pinfo, tree)
    if buf(0, 1):uint() ~= 0xd1 then
        tree:add_expert_info(PI_MALFORMED, PI_ERROR, 'invalid DRW header')
        return
    end

    tree:add(drw_channel_num_F, buf(1, 1))
    tree:add(drw_packet_index_F, buf(2, 2))
    tnp_proto.dissector(buf(4):tvb(), pinfo, tree) -- FIXME
    return 'DRW'
end

function pppp_drw_ack(buf, _, tree)
    if buf(0, 1):uint() ~= 0xd1 then
        tree:add_expert_info(PI_MALFORMED, PI_ERROR, 'invalid DRW header')
        return
    end

    tree:add(drw_ack_channel_num_F, buf(1, 1))

    local packet_count = buf(2, 2)
    tree:add(drw_ack_packet_count_F, packet_count)

    local list = tree:add(pppp_proto, 'ACKs')
    for i = 0, packet_count:uint() - 1 do
        list:add(drw_ack_packet_index_F, buf(4 + i * 2, 2))
    end

    return 'DRW_ACK'
end

pppp_table = {
    [0x00] = pppp_hello,
    [0x01] = pppp_hello_ack,
    [0x14] = pppp_dev_login_key,
    [0x15] = pppp_dev_login_key_ack,
    [0x40] = pppp_punch_to,
    [0x41] = pppp_punch_pkt,
    [0x8a] = pppp_rly_tcp_to,
    [0x8b] = pppp_rly_tcp_result,
    [0xd0] = pppp_drw,
    [0xd1] = pppp_drw_ack,
    [0xe0] = pppp_alive,
    [0xe1] = pppp_alive_ack,
}

function pppp_proto.dissector(buf, pinfo, tree)
    local idx = 0
    while idx < buf:len()
    do
        if buf(idx, 1):uint() ~= 0xf1 then
            return -- invalid
        end

        local packet_size = buf(idx + 2, 2)
        if idx + 4 + packet_size:uint() > buf:len() then
            pinfo.desegment_offset = idx
            pinfo.desegment_len = idx + 4 + packet_size:uint() - buf:len()
            return
        end

        idx = idx + 4 + packet_size:uint()
    end

    local packet_names = ''
    local idx = 0
    while idx < buf:len()
    do
        local packet_type = buf(idx + 1, 1)
        local packet_size = buf(idx + 2, 2)
        local packet_buf = buf(idx + 4, packet_size:uint())

        local subtree = tree:add(pppp_proto, buf(idx, 4 + packet_size:uint()), "PPPP")
        local header = subtree:add(pppp_proto, buf(idx, 4), "Header")
        header:add(header_type_F, packet_type)
        header:add(header_size_F, packet_size)

        local pppp_func = pppp_table[packet_type:uint()]
        if pppp_func == nil then
            packet_names = packet_names .. 'UNKNOWN,'
            subtree:add_tvb_expert_info(pppp_unknown_E, packet_buf, 'unknown packet type: 0x' .. packet_type:bytes():tohex())
            subtree:set_text('PPPP (UNKNOWN)')
        else
            local packet_name = pppp_func(packet_buf:tvb(), pinfo, subtree:add(pppp_proto, packet_buf, "Body"))
            if packet_name == nil then
                packet_names = packet_names .. 'UNKNOWN,'
                subtree:set_text('PPPP (UNKNOWN)')
            else
                packet_names = packet_names .. packet_name .. ','
                subtree:set_text('PPPP (' .. packet_name .. ')')
            end
        end

        idx = idx + 4 + packet_size:uint()
    end

    pinfo.cols.protocol = 'PPPP'
    pinfo.cols.info = string.sub(packet_names, 1, -2)
end

pppp_proto:register_heuristic("tcp", heuristic_checker)
pppp_proto:register_heuristic("udp", heuristic_checker)

DissectorTable.get('tcp.port'):add_for_decode_as(pppp_proto)

tnp_proto = Proto("tnp", "TNP")

tnp_version_F = ProtoField.uint8("tnp.version", "Version")
tnp_io_type_F = ProtoField.uint8("tnp.io_type", "IO type")
tnp_size_F = ProtoField.uint32("tnp.size", "Size")

tnp_io_ctrl_type_F = ProtoField.uint16("tnp.io_ctrl.type", "Command type")
tnp_io_ctrl_num_F = ProtoField.uint16("tnp.io_ctrl.num", "Command number")
tnp_io_ctrl_header_size_F = ProtoField.uint16("tnp.io_ctrl.header_size", "Header size")
tnp_io_ctrl_data_size_F = ProtoField.uint16("tnp.io_ctrl.data_size", "Data size")
tnp_io_ctrl_auth_info_F = ProtoField.stringz("tnp.io_ctrl.auth_info", "Auth info")
tnp_io_ctrl_auth_result_F = ProtoField.int32("tnp.io_ctrl.auth_result", "Auth result")
tnp_io_ctrl_data_F = ProtoField.bytes("tnp.io_ctrl.data", "Data")

tnp_av_codec_id_F = ProtoField.uint16("tnp.av.codec_id", "Codec ID")
tnp_av_flags_F = ProtoField.uint8("tnp.av.flags", "Flags")
tnp_av_live_flag_F = ProtoField.uint8("tnp.av.live_flag", "Live flag")
tnp_av_online_num_F = ProtoField.uint8("tnp.av.online_num", "Online number")
tnp_av_use_count_F = ProtoField.uint8("tnp.av.use_count", "Use count")
tnp_av_frame_num_F = ProtoField.uint16("tnp.av.frame_num", "Frame number")
tnp_av_video_width_F = ProtoField.uint16("tnp.av.video_width", "Video width")
tnp_av_video_height_F = ProtoField.uint16("tnp.av.video_height", "Video height")
tnp_av_timestamp_F = ProtoField.uint32("tnp.av.timestamp", "Timestamp")
tnp_av_is_day_F = ProtoField.uint8("tnp.av.is_day", "Is day")
tnp_av_cover_state_F = ProtoField.uint8("tnp.av.cover_state", "Cover state")
tnp_av_out_loss_F = ProtoField.uint8("tnp.av.out_loss", "Out loss")
tnp_av_in_loss_F = ProtoField.uint8("tnp.av.in_loss", "In loss")
tnp_av_timestamp_ms_F = ProtoField.uint32("tnp.av.timestamp_ms", "Timestamp (ms)")
tnp_av_frame_data_F = ProtoField.bytes("tnp.av.frame_data", "Frame data")

tnp_proto.fields = {
    tnp_version_F, tnp_io_type_F, tnp_size_F,

    tnp_io_ctrl_type_F, tnp_io_ctrl_num_F, tnp_io_ctrl_header_size_F, tnp_io_ctrl_data_size_F, tnp_io_ctrl_auth_info_F,
    tnp_io_ctrl_auth_result_F, tnp_io_ctrl_data_F,

    tnp_av_codec_id_F, tnp_av_flags_F, tnp_av_live_flag_F, tnp_av_online_num_F, tnp_av_use_count_F, tnp_av_frame_num_F, tnp_av_video_width_F,
    tnp_av_video_height_F, tnp_av_timestamp_F, tnp_av_is_day_F, tnp_av_cover_state_F, tnp_av_out_loss_F, tnp_av_in_loss_F, tnp_av_timestamp_ms_F,
    tnp_av_frame_data_F
}

function tnp_io_ctrl(buf, pinfo, tree)
    tree:add(tnp_io_ctrl_type_F, buf(0, 2))
    tree:add(tnp_io_ctrl_num_F, buf(2, 2))
    tree:add(tnp_io_ctrl_header_size_F, buf(4, 2))
    local data_size = buf(6, 2)
    tree:add(tnp_io_ctrl_data_size_F, data_size)
    tree:add(tnp_io_ctrl_auth_info_F, buf(8, 32))     -- FIXME auth_info or auth_result
    tree:add(tnp_io_ctrl_data_F, buf(40, data_size:uint()))
end

function tnp_av(buf, pinfo, tree)
    tree:add(tnp_av_codec_id_F, buf(0, 2))
    tree:add(tnp_av_flags_F, buf(2, 1))
    tree:add(tnp_av_live_flag_F, buf(3, 1))
    tree:add(tnp_av_online_num_F, buf(4, 1))
    tree:add(tnp_av_use_count_F, buf(5, 1))
    tree:add(tnp_av_frame_num_F, buf(6, 2))
    tree:add(tnp_av_video_width_F, buf(8, 2))
    tree:add(tnp_av_video_height_F, buf(10, 2))
    tree:add(tnp_av_timestamp_F, buf(12, 4))
    tree:add(tnp_av_is_day_F, buf(16, 1))
    tree:add(tnp_av_cover_state_F, buf(17, 1))
    tree:add(tnp_av_out_loss_F, buf(18, 1))
    tree:add(tnp_av_in_loss_F, buf(19, 1))
    tree:add(tnp_av_timestamp_ms_F, buf(20, 4))
    tree:add(tnp_av_frame_data_F, buf(24))
end

function tnp_proto.dissector(buf, pinfo, tree)
    local idx = 0
    while idx < buf:len()
    do
        local version = buf(idx, 1)
        local io_type = buf(idx+1, 1)
        local size = buf(idx+4, 4)

        local subtree = tree:add(tnp_proto, buf(idx), 'TNP')
        subtree:add(tnp_version_F, version)
        subtree:add(tnp_io_type_F, io_type)
        subtree:add(tnp_size_F, size)

        local data_buf = buf(idx+8)

        if size:uint() > data_buf:len() then
            subtree:add_expert_info(PI_REASSEMBLE, PI_WARN, 'packet continues somewhere')
        end

        if io_type:uint() == 1 then
            tnp_av(data_buf:tvb(), pinfo, subtree:add(tnp_proto, data_buf, 'Video'))
            subtree:set_text('TNP (Video)')
        elseif io_type:uint() == 2 then
            tnp_av(data_buf:tvb(), pinfo, subtree:add(tnp_proto, data_buf, 'Audio'))
            subtree:set_text('TNP (Audio)')
        elseif io_type:uint() == 3 then
            tnp_io_ctrl(data_buf:tvb(), pinfo, subtree:add(tnp_proto, data_buf, 'IOCtrl'))
            subtree:set_text('TNP (IOCtrl)')
        else
            subtree:add_expert_info(PI_MALFORMED, PI_ERROR, 'unknown io type: ' .. tostring(io_type:uint()))
        end

        idx = idx + 8 + size:uint()
    end
end

