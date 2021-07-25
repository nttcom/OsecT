from dpkt.compat import compat_ord
import dpkt
import ipaddress
from unicodedata import category
import re
import struct
import glob
import os
import shutil
import zipfile

from datetime import datetime, timedelta
from decimal import Decimal

from common.common_config import PCAP_COMPLETE_FILE_PATH, PCAP_COMPLETE_ARCHIVES_FILE_PATH, \
    PCAP_COMPLETE_COMPRESSION_LIMIT_DATE, PCAP_COMPLETE_ARCHIVES_DELETE_LIMIT_DATE, PCAP_COMPLETE_ARCHIVES_DELETE_LIMIT_CAPACITY


def deleteCc(s):
    r = ''
    for c in s:
        if category(c) == 'Cc':
            continue
        r += c

    return r


def parseDHCP(udpData):
    """
    UDPデータをパースする（DHCP用）

    :param udpData: UDPデータ
    :return: ie（ie[0]:Hostname, ie[1]:Parameter List, ie[2]:Class Id）
    """

    ie = ['-', '-', '-']

    try:
        dhcp = dpkt.dhcp.DHCP(udpData)
    except:
        return None

    for (t, v) in dhcp.opts:
        if t == 12:
            ie[0] = v.decode(encoding='utf-8', errors='backslashreplace').replace('\0', '')
            ie[0] = deleteCc(ie[0])
        elif t == 55:
            ie[1] = ','.join('%d' % compat_ord(b) for b in v)
            ie[1].replace('\0', '')
        elif t == 60:
            ie[2] = v.decode(encoding='utf-8', errors='backslashreplace').replace('\0', '')
            ie[2] = deleteCc(ie[2])

    return ie


def parseNBNS(udpData):
    """
    UDPデータをパースする（NetBIOS Name Service用）

    :param udpData: UDPデータ
    :return: ie（ie[0]:Name, ie[1]:TTL, ie[2]:Service Type）
    """

    ie = ['-', '-', '-']

    try:
        nb = dpkt.netbios.NS(udpData)
    except:
        return None

    if nb.opcode != 5:
        return None

    if len(nb.ar) <= 0:
        return None

    for r in nb.ar:
        _name = []
        lines = r.name
        if type(lines[0]) == int:
            [_name.append(chr(((lines[i] - 0x41) << 4) | ((lines[i + 1] - 0x41) & 0xf))) for i in range(0, 32, 2)]
        else:
            [_name.append(chr(((ord(lines[i]) - 0x41) << 4) | ((ord(lines[i + 1]) - 0x41) & 0xf))) for i in
             range(0, 32, 2)]

        if r.rdata[0] >> 7:  # NameType = Group(0) ? Unique(1)
            return None
        # continue
        else:
            flag = (_name[-1])[-1]
            _srv = ''
            if '\x00' in flag:
                _srv = 'Workstation'
            elif '\x03' in flag:
                _srv = 'Messenger'
            elif '\x06' in flag:
                _srv = 'RAS Server'
            elif '\x1F' in flag:
                _srv = 'NetDDE'
            elif '\x20' in flag:
                _srv = 'Server'
            elif '\x21' in flag:
                _srv = 'RAS Client'
            elif '\xBE' in flag:
                _srv = 'Network Monitor Agent'
            elif '\xBF' in flag:
                _srv = 'Network Monitor Application'
            elif '\x1D' in flag:
                _srv = 'Master Browser'
            elif '\x1B' in flag:
                _srv = 'Domain Master Browser'
            elif '\x1C' in flag:
                _srv = 'Domain Controllers'
            elif '\x1E' in flag:
                _srv = 'Browser Service Elections'
            elif '\x01' in flag:
                _srv = 'Master Browser'
            else:
                _srv = 'Unknown'

        ie[0] = ''.join(_name[:-2]).rstrip().replace('\0', '')
        ie[0] = deleteCc(ie[0])
        ie[1] = str(r.ttl)
        ie[2] = _srv

    return ie


def parseMWBP(udpData):
    """
    UDPデータをパースする（NetBIOS Datagram Service用）

    :param udpData: UDPデータ
    :return: ie（ie[0]:Server Name, ie[1]:OS Version, ie[2]:Service Type, ie[3]:Browser Verion, ie[4]:Signeture, ie[5]:Host Comment）
    """

    ie = ['-', '-', '-', '-', '-', '-']

    msbr = udpData[168:]
    msg_type = msbr[0]
    if msg_type == 0x01 or msg_type == 0x0F:
        fmt = '<BBL16sBBLBBH' + str(len(msbr) - 32) + 's'
        _cmd, _uc, _up, _host, _osma, _osmn, _type, _brma, _brmn, _sig, _com = struct.unpack_from(fmt, msbr)
        ie[0] = _host.decode(encoding='utf-8', errors='backslashreplace').replace('\0', '') if type(
            _host) != str else _host
        ie[0] = deleteCc(ie[0])
        ie[1] = str(_osma) + '.' + str(_osmn)
        ie[2] = hex(_type)
        ie[3] = str(_brma) + '.' + str(_brmn)
        ie[4] = hex(_sig)
        ie[5] = _com.decode(encoding='utf-8', errors='backslashreplace').replace('\0', '') if type(
            _com) != str else _com
        ie[5] = deleteCc(ie[5])
    else:
        return None

    return ie


def parseSSDP(udpData):
    """
    UDPデータをパースする（SSDP用）

    :param udpData: UDPデータ
    :return: ie（ie[0]:Method, ie[1]:SERVER or USER-AGENT
    """

    ie = ['-', '-']

    try:
        msg = udpData.decode('utf-8')
    except:
        return ie

    if msg.startswith('NOTIFY * HTTP/1.1'):
        ie[0] = 'NOTIFY'
        for line in msg.split('\r\n'):
            v = re.split('\s*:\s*', line, 1)
            if v[0].upper() == 'SERVER':
                ie[1] = v[1]
                break

    elif msg.startswith('M-SEARCH * HTTP/1.1'):
        ie[0] = 'M-SEARCH Request'
        for line in msg.split('\r\n'):
            v = re.split('\s*:\s*', line, 1)
            if v[0].upper() == 'USER-AGENT':
                ie[1] = v[1]
                break

    elif msg.startswith('HTTP/1.1 200 OK'):
        ie[0] = 'M-SEARCH Response'
        for line in msg.split('\r\n'):
            v = re.split('\s*:\s*', line, 1)
            if v[0].upper() == 'SERVER':
                ie[1] = v[1]
                break
    return ie


def parseDHCPv6(udpData):
    """
    UDPデータをパースする（DHCP用）

    :param udpData: UDPデータ
    :return: ie（ie[0]:Hostname, ie[1]:FingerPrint, ie[2]:Enterprise Number, ie[3]:Vendor Class）
    """

    ie = ['-', '-', '-', '-']

    (msg_type,) = struct.unpack_from('!B', udpData)
    b = b'\x00' + udpData[1:]  # unpack xid as a 4-byte integer
    length = struct.calcsize('!H16s16s') if msg_type == 12 or msg_type == 13 else struct.calcsize('!I')
    options, offset = [], 0

    # 各option fieldをパース
    if len(b) > length:
        tmp_buf = b[length:]
        while len(tmp_buf) > offset:
            opt_buf = tmp_buf[offset:]
            # optionコード
            code = struct.unpack_from('!H', opt_buf)[0]
            # optionのlength
            tmp_length = struct.unpack_from('!H', opt_buf[2:])[0]
            # optionコードと1option分のlengthとbyte列をoptionsに追加
            options.append((code, tmp_length, struct.unpack_from('%ds' % tmp_length, opt_buf[4:])[0]))
            offset += tmp_length + 4
        length += len(tmp_buf)

    # DHCPv6で、抽出するのはhostname、fingerprint、enterprise
    fingerprint = []
    for i in options:
        if i[0] == 39:  # hostname
            tmp_offset = i[1] - 2
            ie[0] = struct.unpack_from('%ds' % tmp_offset, i[2], 2)[0].decode()
            ie[0] = deleteCc(ie[0])
        elif i[0] == 6:  # fingerprint
            tmp_offset = int(len(i[2]) / 2)
            fingerprint.extend(struct.unpack('!%dH' % tmp_offset, i[2]))
        elif i[0] == 16:  # fingerprint and enterprise
            tmp_offset = i[1] - 6
            ep_num, vendor = struct.unpack('!ixx%ds' % tmp_offset, i[2])
            fingerprint.append(ep_num)
            ie[2] = str(ep_num)
            ie[3] = vendor.decode()
            ie[3] = deleteCc(ie[3])

    # fingerprintをリストから文字列に変換
    ie[1] = ','.join(map(str, fingerprint)) or '-'

    return ie


def pcap2log(pcapFile, logDir):
    """
    pcapファイルを読み込んでlogファイルに保存する

    :param pcapFile: pcapファイルのパス
    :param logDir: 出力先ディレクトリ
    """
    last_msearch = {}
    p = dpkt.pcap.Reader(open(pcapFile, 'rb'))
    fDHCP = open(logDir + '/dhcp2.log', 'w')
    fDHCP.write('#fields ts	SrcIP	SrcMAC	Hostname	ParameterList	ClassId\n')
    fNBNS = open(logDir + '/netbios-ns.log', 'w')
    fNBNS.write('#fields ts	SrcIP	SrcMAC	Name	TTL	ServiceType\n')
    fMWBP = open(logDir + '/mswin-browser.log', 'w')
    fMWBP.write(
        '#fields ts	SrcIP	SrcMAC	ServerName	OSVersion	ServerType	BrowserVersion	Signature	HostComment\n')
    fSSDP = open(logDir + '/ssdp.log', 'w')
    fSSDP.write('#fields ts SrcIP   SrcMAC  Method	SERVER or USER-AGENT\n')
    fDHCPv6 = open(logDir + '/dhcpv6.log', 'w')
    fDHCPv6.write('#fields ts SrcIP   SrcMAC  Hostname        FingerPrint	EnterpriseNumber	VendorClass\n')
    for t, buf in p:
        eth = dpkt.ethernet.Ethernet(buf)
        if type(eth.data) == dpkt.ip.IP or type(eth.data) == dpkt.ip6.IP6:
            ip = eth.data
            if type(ip.data) == dpkt.udp.UDP:
                srcMacAddress = ':'.join('%02x' % compat_ord(b) for b in eth.src)
                srcIpAddress = str(ipaddress.ip_address(ip.src))
                udp = ip.data
                if udp.dport == 67 and type(eth.data) == dpkt.ip.IP:
                    ie = parseDHCP(udp.data)
                    if ie == None:
                        continue
                    fDHCP.write('{:6f}'.format(t) + '\t' + srcIpAddress + '\t' + srcMacAddress + '\t' + '\t'.join(
                        [str(i) for i in ie]) + '\n')

                elif udp.dport == 137:
                    ie = parseNBNS(udp.data)
                    if ie == None:
                        continue
                    fNBNS.write('{:6f}'.format(t) + '\t' + srcIpAddress + '\t' + srcMacAddress + '\t' + '\t'.join(
                        [str(i) for i in ie]) + '\n')

                elif udp.dport == 138:
                    ie = parseMWBP(udp.data)
                    if ie == None:
                        continue
                    fMWBP.write('{:6f}'.format(t) + '\t' + srcIpAddress + '\t' + srcMacAddress + '\t' + '\t'.join(
                        [str(i) for i in ie]) + '\n')

                elif udp.dport == 1900:
                    ie = parseSSDP(udp.data)
                    if ie == None:
                        continue
                    fSSDP.write('{:6f}'.format(t) + '\t' + srcIpAddress + '\t' + srcMacAddress + '\t' + '\t'.join(
                        [str(i) for i in ie]) + '\n')

                    if ie[0] == 'M-SEARCH Request' and udp.sport != 1900:
                        src = srcIpAddress + ':' + str(udp.sport)
                        last_msearch[src] = t

                elif udp.dport == 547 and type(eth.data) == dpkt.ip6.IP6:
                    ie = parseDHCPv6(udp.data)
                    if ie == None:
                        continue
                    fDHCPv6.write('{:6f}'.format(t) + '\t' + srcIpAddress + '\t' + srcMacAddress + '\t' + '\t'.join(
                        [str(i) for i in ie]) + '\n')

                else:
                    dst = str(ipaddress.ip_address(ip.dst)) + ':' + str(udp.dport)
                    if dst in last_msearch:
                        if t < last_msearch[dst] + 5:
                            ie = parseSSDP(udp.data)
                            if ie == None:
                                continue
                            fSSDP.write(
                                '{:6f}'.format(t) + '\t' + srcIpAddress + '\t' + srcMacAddress + '\t' + '\t'.join(
                                    [str(i) for i in ie]) + '\n')
    fDHCP.close()
    fNBNS.close()
    fMWBP.close()
    fSSDP.close()
    fDHCPv6.close()

    return


def exec_complete_to_archives(logger):
    # complete配下の保持期限切れファイルとディレクトリを圧縮
    file_compression_date_infos = _get_file_date_info(PCAP_COMPLETE_FILE_PATH)
    target_compression_list = _get_target_list(file_compression_date_infos, PCAP_COMPLETE_COMPRESSION_LIMIT_DATE)
    _compress_file(target_compression_list)

    if len(target_compression_list):
        for target_compression in target_compression_list:
            logger.info('compression: %s' % (target_compression))
    else:
        logger.info('There is no compression file or directory')

    # complete_archives配下の保持期限切れファイルの削除
    file_date_archives_infos = _get_file_date_info(PCAP_COMPLETE_ARCHIVES_FILE_PATH)
    target_archives_list = _get_target_list(file_date_archives_infos, PCAP_COMPLETE_ARCHIVES_DELETE_LIMIT_DATE)
    _delete_file_and_dir(target_archives_list)

    if len(target_archives_list):
        for target_archives in target_archives_list:
            logger.info('delete archives: %s' % (target_archives))
    else:
        logger.info('There is no archives file to delete')

    # 保持容量上限超過ファイルの削除
    file_size_infos = _get_file_size_info()
    # サイズ容量合計計算
    total_path_size = _calc_size_sum(file_size_infos)
    # ギガバイトに変換
    total_size = _convert_size_giga_byte(total_path_size)

    if _is_capacity_over(total_size):
        target_capacity_over_list = _get_target_capacity_over_list(file_size_infos, total_size)
        _delete_file_and_dir(target_capacity_over_list)

        for target_capacity_over in target_capacity_over_list:
            logger.info('capacity over: %s' % (target_capacity_over))
    else:
        logger.info('There is no capacity over file. %s/%s GB' % (total_size, PCAP_COMPLETE_ARCHIVES_DELETE_LIMIT_CAPACITY))


def _get_file_date_info(target_path):
    """
    引数に指定されたパス配下に存在するファイルとディレクトリの名前と日付の情報を取得する

    :param target_path: 対象パス
    :return: file_date_infos
    """
    file_names = glob.glob(os.path.join(target_path, '**'))
    file_date_infos = [
        {
            'file_name': file_name,
            'file_date': datetime.fromtimestamp(os.path.getmtime(file_name)).strftime("%Y%m%d"),
        }
        for file_name in file_names
    ]

    file_date_infos = sorted(file_date_infos, key=lambda x: x['file_name'])

    return file_date_infos


def _get_target_list(file_date_infos, limit_date):
    """
    引数で指定した保有日付を超過している対象を取得する

    :param file_date_infos: ファイル情報一覧
    :param limit_date: 保有日付
    :return: target_file_list
    """
    limit_date = (datetime.now() + timedelta(days=-limit_date)).strftime("%Y%m%d")

    target_file_list = []
    for file_date_info in file_date_infos:
        file_name = file_date_info['file_name']
        file_date = file_date_info['file_date']

        if file_date < limit_date:
            target_file_list.append(file_name)

    target_file_list = sorted(target_file_list)

    return target_file_list


def _compress_file(target_compression_list):
    """
    引数に指定されたパス対象を圧縮する、圧縮後は対象を削除する

    :param target_compression_list: 対象パス一覧
    """
    for target_compression in target_compression_list:
        file_name = os.path.basename(target_compression)
        compression_file = os.path.join(PCAP_COMPLETE_ARCHIVES_FILE_PATH, '%s.zip' % (file_name))
        compression_path = os.path.join(PCAP_COMPLETE_ARCHIVES_FILE_PATH, file_name)

        if os.path.isfile(target_compression):
            # ファイル
            with zipfile.ZipFile(compression_file, 'w', compression=zipfile.ZIP_DEFLATED) as compression_zip:
                compression_zip.write(target_compression, arcname=file_name)
            # 圧縮後ファイル削除
            os.remove(target_compression)
        else:
            # ディレクトリ
            shutil.make_archive(compression_path, 'zip', root_dir=target_compression)
            # 圧縮後ディレクトリ削除
            shutil.rmtree(target_compression)


def _delete_file_and_dir(target_path_list):
    """
    引数に指定されたパス対象を削除する

    :param target_path_list: 対象パス一覧
    """
    for target_path in target_path_list:
        if os.path.isfile(target_path):
            # ファイル削除
            os.remove(target_path)
        else:
            # ディレクトリ削除
            shutil.rmtree(target_path)


def _get_file_size_info():
    """
    completeとarchivesのパス配下に存在するファイルとディレクトリの名前、日付、サイズの情報を取得する

    :return: file_size_infos
    """
    target_path_dict = {
        'complete': PCAP_COMPLETE_FILE_PATH,
        'archives': PCAP_COMPLETE_ARCHIVES_FILE_PATH,
    }

    file_size_infos = {}
    for path_type, target_path in target_path_dict.items():
        file_paths = glob.glob(os.path.join(target_path, '**'))

        file_info_list = []
        for file_path in file_paths:
            if os.path.isfile(file_path):
                # ファイル
                file_info = {
                    'file_name': file_path,
                    'file_size': os.path.getsize(file_path),
                    'file_date': datetime.fromtimestamp(os.path.getmtime(file_path)).strftime("%Y%m%d"),
                    'file_type': 'file',
                }
                file_info_list.append(file_info)
            else:
                # ディレクトリ
                file_names = glob.glob(os.path.join(file_path, '**'), recursive=True)
                total_path_size = sum((
                    os.path.getsize(file_name)
                    for file_name in file_names
                    if os.path.isfile(file_name)
                ))
                file_info = {
                    'file_name': file_path,
                    'file_size': total_path_size,
                    'file_date': datetime.fromtimestamp(os.path.getmtime(file_path)).strftime("%Y%m%d"),
                    'file_type': 'dir',
                }
                file_info_list.append(file_info)

        file_info_list = sorted(file_info_list, key=lambda x: (x['file_date'], x['file_name']))
        file_size_infos[path_type] = file_info_list

    return file_size_infos


def _calc_size_sum(file_size_infos):
    """
    引数で指定されたファイル情報の合計ファイルサイズを計算する

    :param file_size_infos: ファイル情報一覧
    :return: total_size
    """
    total_size = sum((
        file_info['file_size']
        for path_type, file_infos in file_size_infos.items()
        for file_info in file_infos
    ))

    return total_size


def _convert_size_giga_byte(size_bytes):
    """
    引数で指定されたファイル情報の合計ファイルサイズを計算する

    :param size_bytes: バイト値
    :return: giga_byte
    """
    giga_byte = round(Decimal(size_bytes / 1024**3), 9)

    return giga_byte


def _is_capacity_over(total_size):
    """
    保持容量を超過しているか判断

    :param total_size: 合計バイト値
    :return: boolean型（True/False）
    """
    if total_size > PCAP_COMPLETE_ARCHIVES_DELETE_LIMIT_CAPACITY:
        # 保持容量以上
        return True
    else:
        # 保持容量以下
        return False


def _get_target_capacity_over_list(file_size_infos, total_size):
    """
    保持容量以下になるように削除対象を取得する

    :param file_size_infos: ファイル情報一覧
    :param total_size: 合計バイト値
    :return: target_delete_files
    """
    archives_info_file_list = [
        file_size_info
        for file_size_info in file_size_infos['archives']
        if file_size_info['file_type'] == 'file'
    ]
    complete_info_dir_list = [
        file_size_info
        for file_size_info in file_size_infos['complete']
        if file_size_info['file_type'] == 'dir'
    ]
    complete_info_file_list = [
        file_size_info
        for file_size_info in file_size_infos['complete']
        if file_size_info['file_type'] == 'file'
    ]

    target_delete_files = []
    delete_file_size = 0
    limit_size = total_size - delete_file_size
    for info_file in archives_info_file_list:
        if limit_size < PCAP_COMPLETE_ARCHIVES_DELETE_LIMIT_CAPACITY:
            return target_delete_files

        target_delete_files.append(info_file['file_name'])
        delete_file_size = _convert_size_giga_byte(info_file['file_size'])
        limit_size -= delete_file_size

    for info_file in complete_info_dir_list:
        if limit_size < PCAP_COMPLETE_ARCHIVES_DELETE_LIMIT_CAPACITY:
            return target_delete_files

        target_delete_files.append(info_file['file_name'])
        delete_file_size = _convert_size_giga_byte(info_file['file_size'])
        limit_size -= delete_file_size

    for info_file in complete_info_file_list:
        if limit_size < PCAP_COMPLETE_ARCHIVES_DELETE_LIMIT_CAPACITY:
            return target_delete_files

        target_delete_files.append(info_file['file_name'])
        delete_file_size = _convert_size_giga_byte(info_file['file_size'])
        limit_size -= delete_file_size

    return target_delete_files
