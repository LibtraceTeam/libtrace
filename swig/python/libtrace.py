# This file was created automatically by SWIG.
# Don't modify this file, modify the SWIG interface instead.
# This file is compatible with both classic and new-style classes.

import _libtrace

def _swig_setattr(self,class_type,name,value):
    if (name == "this"):
        if isinstance(value, class_type):
            self.__dict__[name] = value.this
            if hasattr(value,"thisown"): self.__dict__["thisown"] = value.thisown
            del value.thisown
            return
    method = class_type.__swig_setmethods__.get(name,None)
    if method: return method(self,value)
    self.__dict__[name] = value

def _swig_getattr(self,class_type,name):
    method = class_type.__swig_getmethods__.get(name,None)
    if method: return method(self)
    raise AttributeError,name

import types
try:
    _object = types.ObjectType
    _newclass = 1
except AttributeError:
    class _object : pass
    _newclass = 0
del types


class in_addr(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, in_addr, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, in_addr, name)
    def __init__(self): raise RuntimeError, "No constructor defined"
    def __repr__(self):
        return "<C in_addr instance at %s>" % (self.this,)
    __swig_setmethods__["s_addr"] = _libtrace.in_addr_s_addr_set
    __swig_getmethods__["s_addr"] = _libtrace.in_addr_s_addr_get
    if _newclass:s_addr = property(_libtrace.in_addr_s_addr_get, _libtrace.in_addr_s_addr_set)

class in_addrPtr(in_addr):
    def __init__(self, this):
        _swig_setattr(self, in_addr, 'this', this)
        if not hasattr(self,"thisown"): _swig_setattr(self, in_addr, 'thisown', 0)
        _swig_setattr(self, in_addr,self.__class__,in_addr)
_libtrace.in_addr_swigregister(in_addrPtr)

class libtrace_ip(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, libtrace_ip, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, libtrace_ip, name)
    def __init__(self): raise RuntimeError, "No constructor defined"
    def __repr__(self):
        return "<C libtrace_ip instance at %s>" % (self.this,)
    __swig_setmethods__["ip_hl"] = _libtrace.libtrace_ip_ip_hl_set
    __swig_getmethods__["ip_hl"] = _libtrace.libtrace_ip_ip_hl_get
    if _newclass:ip_hl = property(_libtrace.libtrace_ip_ip_hl_get, _libtrace.libtrace_ip_ip_hl_set)
    __swig_setmethods__["ip_v"] = _libtrace.libtrace_ip_ip_v_set
    __swig_getmethods__["ip_v"] = _libtrace.libtrace_ip_ip_v_get
    if _newclass:ip_v = property(_libtrace.libtrace_ip_ip_v_get, _libtrace.libtrace_ip_ip_v_set)
    __swig_setmethods__["ip_tos"] = _libtrace.libtrace_ip_ip_tos_set
    __swig_getmethods__["ip_tos"] = _libtrace.libtrace_ip_ip_tos_get
    if _newclass:ip_tos = property(_libtrace.libtrace_ip_ip_tos_get, _libtrace.libtrace_ip_ip_tos_set)
    __swig_setmethods__["ip_ttl"] = _libtrace.libtrace_ip_ip_ttl_set
    __swig_getmethods__["ip_ttl"] = _libtrace.libtrace_ip_ip_ttl_get
    if _newclass:ip_ttl = property(_libtrace.libtrace_ip_ip_ttl_get, _libtrace.libtrace_ip_ip_ttl_set)
    __swig_setmethods__["ip_p"] = _libtrace.libtrace_ip_ip_p_set
    __swig_getmethods__["ip_p"] = _libtrace.libtrace_ip_ip_p_get
    if _newclass:ip_p = property(_libtrace.libtrace_ip_ip_p_get, _libtrace.libtrace_ip_ip_p_set)
    __swig_getmethods__["ip_sum"] = _libtrace.libtrace_ip_ip_sum_get
    if _newclass:ip_sum = property(_libtrace.libtrace_ip_ip_sum_get)
    __swig_getmethods__["ip_len"] = _libtrace.libtrace_ip_ip_len_get
    if _newclass:ip_len = property(_libtrace.libtrace_ip_ip_len_get)
    __swig_getmethods__["ip_id"] = _libtrace.libtrace_ip_ip_id_get
    if _newclass:ip_id = property(_libtrace.libtrace_ip_ip_id_get)
    __swig_getmethods__["ip_off"] = _libtrace.libtrace_ip_ip_off_get
    if _newclass:ip_off = property(_libtrace.libtrace_ip_ip_off_get)
    __swig_getmethods__["ip_src"] = _libtrace.libtrace_ip_ip_src_get
    if _newclass:ip_src = property(_libtrace.libtrace_ip_ip_src_get)
    __swig_getmethods__["ip_dst"] = _libtrace.libtrace_ip_ip_dst_get
    if _newclass:ip_dst = property(_libtrace.libtrace_ip_ip_dst_get)

class libtrace_ipPtr(libtrace_ip):
    def __init__(self, this):
        _swig_setattr(self, libtrace_ip, 'this', this)
        if not hasattr(self,"thisown"): _swig_setattr(self, libtrace_ip, 'thisown', 0)
        _swig_setattr(self, libtrace_ip,self.__class__,libtrace_ip)
_libtrace.libtrace_ip_swigregister(libtrace_ipPtr)
IP_RF = _libtrace.IP_RF
IP_DF = _libtrace.IP_DF
IP_MF = _libtrace.IP_MF
IP_OFFMASK = _libtrace.IP_OFFMASK

class libtrace_tcp(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, libtrace_tcp, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, libtrace_tcp, name)
    def __init__(self): raise RuntimeError, "No constructor defined"
    def __repr__(self):
        return "<C libtrace_tcp instance at %s>" % (self.this,)
    __swig_setmethods__["res1"] = _libtrace.libtrace_tcp_res1_set
    __swig_getmethods__["res1"] = _libtrace.libtrace_tcp_res1_get
    if _newclass:res1 = property(_libtrace.libtrace_tcp_res1_get, _libtrace.libtrace_tcp_res1_set)
    __swig_setmethods__["doff"] = _libtrace.libtrace_tcp_doff_set
    __swig_getmethods__["doff"] = _libtrace.libtrace_tcp_doff_get
    if _newclass:doff = property(_libtrace.libtrace_tcp_doff_get, _libtrace.libtrace_tcp_doff_set)
    __swig_setmethods__["fin"] = _libtrace.libtrace_tcp_fin_set
    __swig_getmethods__["fin"] = _libtrace.libtrace_tcp_fin_get
    if _newclass:fin = property(_libtrace.libtrace_tcp_fin_get, _libtrace.libtrace_tcp_fin_set)
    __swig_setmethods__["syn"] = _libtrace.libtrace_tcp_syn_set
    __swig_getmethods__["syn"] = _libtrace.libtrace_tcp_syn_get
    if _newclass:syn = property(_libtrace.libtrace_tcp_syn_get, _libtrace.libtrace_tcp_syn_set)
    __swig_setmethods__["rst"] = _libtrace.libtrace_tcp_rst_set
    __swig_getmethods__["rst"] = _libtrace.libtrace_tcp_rst_get
    if _newclass:rst = property(_libtrace.libtrace_tcp_rst_get, _libtrace.libtrace_tcp_rst_set)
    __swig_setmethods__["psh"] = _libtrace.libtrace_tcp_psh_set
    __swig_getmethods__["psh"] = _libtrace.libtrace_tcp_psh_get
    if _newclass:psh = property(_libtrace.libtrace_tcp_psh_get, _libtrace.libtrace_tcp_psh_set)
    __swig_setmethods__["ack"] = _libtrace.libtrace_tcp_ack_set
    __swig_getmethods__["ack"] = _libtrace.libtrace_tcp_ack_get
    if _newclass:ack = property(_libtrace.libtrace_tcp_ack_get, _libtrace.libtrace_tcp_ack_set)
    __swig_setmethods__["urg"] = _libtrace.libtrace_tcp_urg_set
    __swig_getmethods__["urg"] = _libtrace.libtrace_tcp_urg_get
    if _newclass:urg = property(_libtrace.libtrace_tcp_urg_get, _libtrace.libtrace_tcp_urg_set)
    __swig_setmethods__["res2"] = _libtrace.libtrace_tcp_res2_set
    __swig_getmethods__["res2"] = _libtrace.libtrace_tcp_res2_get
    if _newclass:res2 = property(_libtrace.libtrace_tcp_res2_get, _libtrace.libtrace_tcp_res2_set)
    __swig_getmethods__["source"] = _libtrace.libtrace_tcp_source_get
    if _newclass:source = property(_libtrace.libtrace_tcp_source_get)
    __swig_getmethods__["dest"] = _libtrace.libtrace_tcp_dest_get
    if _newclass:dest = property(_libtrace.libtrace_tcp_dest_get)
    __swig_getmethods__["window"] = _libtrace.libtrace_tcp_window_get
    if _newclass:window = property(_libtrace.libtrace_tcp_window_get)
    __swig_getmethods__["check"] = _libtrace.libtrace_tcp_check_get
    if _newclass:check = property(_libtrace.libtrace_tcp_check_get)
    __swig_getmethods__["urg_ptr"] = _libtrace.libtrace_tcp_urg_ptr_get
    if _newclass:urg_ptr = property(_libtrace.libtrace_tcp_urg_ptr_get)
    __swig_getmethods__["seq"] = _libtrace.libtrace_tcp_seq_get
    if _newclass:seq = property(_libtrace.libtrace_tcp_seq_get)
    __swig_getmethods__["ack_seq"] = _libtrace.libtrace_tcp_ack_seq_get
    if _newclass:ack_seq = property(_libtrace.libtrace_tcp_ack_seq_get)

class libtrace_tcpPtr(libtrace_tcp):
    def __init__(self, this):
        _swig_setattr(self, libtrace_tcp, 'this', this)
        if not hasattr(self,"thisown"): _swig_setattr(self, libtrace_tcp, 'thisown', 0)
        _swig_setattr(self, libtrace_tcp,self.__class__,libtrace_tcp)
_libtrace.libtrace_tcp_swigregister(libtrace_tcpPtr)

class libtrace_udp(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, libtrace_udp, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, libtrace_udp, name)
    def __init__(self): raise RuntimeError, "No constructor defined"
    def __repr__(self):
        return "<C libtrace_udp instance at %s>" % (self.this,)
    __swig_getmethods__["source"] = _libtrace.libtrace_udp_source_get
    if _newclass:source = property(_libtrace.libtrace_udp_source_get)
    __swig_getmethods__["dest"] = _libtrace.libtrace_udp_dest_get
    if _newclass:dest = property(_libtrace.libtrace_udp_dest_get)
    __swig_getmethods__["len"] = _libtrace.libtrace_udp_len_get
    if _newclass:len = property(_libtrace.libtrace_udp_len_get)
    __swig_getmethods__["check"] = _libtrace.libtrace_udp_check_get
    if _newclass:check = property(_libtrace.libtrace_udp_check_get)

class libtrace_udpPtr(libtrace_udp):
    def __init__(self, this):
        _swig_setattr(self, libtrace_udp, 'this', this)
        if not hasattr(self,"thisown"): _swig_setattr(self, libtrace_udp, 'thisown', 0)
        _swig_setattr(self, libtrace_udp,self.__class__,libtrace_udp)
_libtrace.libtrace_udp_swigregister(libtrace_udpPtr)

class libtrace_icmp(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, libtrace_icmp, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, libtrace_icmp, name)
    def __init__(self): raise RuntimeError, "No constructor defined"
    def __repr__(self):
        return "<C libtrace_icmp instance at %s>" % (self.this,)
    __swig_setmethods__["type"] = _libtrace.libtrace_icmp_type_set
    __swig_getmethods__["type"] = _libtrace.libtrace_icmp_type_get
    if _newclass:type = property(_libtrace.libtrace_icmp_type_get, _libtrace.libtrace_icmp_type_set)
    __swig_setmethods__["code"] = _libtrace.libtrace_icmp_code_set
    __swig_getmethods__["code"] = _libtrace.libtrace_icmp_code_get
    if _newclass:code = property(_libtrace.libtrace_icmp_code_get, _libtrace.libtrace_icmp_code_set)
    __swig_setmethods__["checksum"] = _libtrace.libtrace_icmp_checksum_set
    __swig_getmethods__["checksum"] = _libtrace.libtrace_icmp_checksum_get
    if _newclass:checksum = property(_libtrace.libtrace_icmp_checksum_get, _libtrace.libtrace_icmp_checksum_set)
    __swig_getmethods__["un"] = _libtrace.libtrace_icmp_un_get
    if _newclass:un = property(_libtrace.libtrace_icmp_un_get)

class libtrace_icmpPtr(libtrace_icmp):
    def __init__(self, this):
        _swig_setattr(self, libtrace_icmp, 'this', this)
        if not hasattr(self,"thisown"): _swig_setattr(self, libtrace_icmp, 'thisown', 0)
        _swig_setattr(self, libtrace_icmp,self.__class__,libtrace_icmp)
_libtrace.libtrace_icmp_swigregister(libtrace_icmpPtr)

class libtrace_icmp_un(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, libtrace_icmp_un, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, libtrace_icmp_un, name)
    def __init__(self): raise RuntimeError, "No constructor defined"
    def __repr__(self):
        return "<C libtrace_icmp_un instance at %s>" % (self.this,)
    __swig_setmethods__["gateway"] = _libtrace.libtrace_icmp_un_gateway_set
    __swig_getmethods__["gateway"] = _libtrace.libtrace_icmp_un_gateway_get
    if _newclass:gateway = property(_libtrace.libtrace_icmp_un_gateway_get, _libtrace.libtrace_icmp_un_gateway_set)
    __swig_getmethods__["frag"] = _libtrace.libtrace_icmp_un_frag_get
    if _newclass:frag = property(_libtrace.libtrace_icmp_un_frag_get)
    __swig_getmethods__["echo"] = _libtrace.libtrace_icmp_un_echo_get
    if _newclass:echo = property(_libtrace.libtrace_icmp_un_echo_get)

class libtrace_icmp_unPtr(libtrace_icmp_un):
    def __init__(self, this):
        _swig_setattr(self, libtrace_icmp_un, 'this', this)
        if not hasattr(self,"thisown"): _swig_setattr(self, libtrace_icmp_un, 'thisown', 0)
        _swig_setattr(self, libtrace_icmp_un,self.__class__,libtrace_icmp_un)
_libtrace.libtrace_icmp_un_swigregister(libtrace_icmp_unPtr)

class libtrace_icmp_un_frag(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, libtrace_icmp_un_frag, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, libtrace_icmp_un_frag, name)
    def __init__(self): raise RuntimeError, "No constructor defined"
    def __repr__(self):
        return "<C libtrace_icmp_un_frag instance at %s>" % (self.this,)
    __swig_setmethods__["__unused"] = _libtrace.libtrace_icmp_un_frag___unused_set
    __swig_getmethods__["__unused"] = _libtrace.libtrace_icmp_un_frag___unused_get
    if _newclass:__unused = property(_libtrace.libtrace_icmp_un_frag___unused_get, _libtrace.libtrace_icmp_un_frag___unused_set)
    __swig_setmethods__["mtu"] = _libtrace.libtrace_icmp_un_frag_mtu_set
    __swig_getmethods__["mtu"] = _libtrace.libtrace_icmp_un_frag_mtu_get
    if _newclass:mtu = property(_libtrace.libtrace_icmp_un_frag_mtu_get, _libtrace.libtrace_icmp_un_frag_mtu_set)

class libtrace_icmp_un_fragPtr(libtrace_icmp_un_frag):
    def __init__(self, this):
        _swig_setattr(self, libtrace_icmp_un_frag, 'this', this)
        if not hasattr(self,"thisown"): _swig_setattr(self, libtrace_icmp_un_frag, 'thisown', 0)
        _swig_setattr(self, libtrace_icmp_un_frag,self.__class__,libtrace_icmp_un_frag)
_libtrace.libtrace_icmp_un_frag_swigregister(libtrace_icmp_un_fragPtr)

class libtrace_icmp_un_echo(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, libtrace_icmp_un_echo, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, libtrace_icmp_un_echo, name)
    def __init__(self): raise RuntimeError, "No constructor defined"
    def __repr__(self):
        return "<C libtrace_icmp_un_echo instance at %s>" % (self.this,)
    __swig_setmethods__["id"] = _libtrace.libtrace_icmp_un_echo_id_set
    __swig_getmethods__["id"] = _libtrace.libtrace_icmp_un_echo_id_get
    if _newclass:id = property(_libtrace.libtrace_icmp_un_echo_id_get, _libtrace.libtrace_icmp_un_echo_id_set)
    __swig_setmethods__["sequence"] = _libtrace.libtrace_icmp_un_echo_sequence_set
    __swig_getmethods__["sequence"] = _libtrace.libtrace_icmp_un_echo_sequence_get
    if _newclass:sequence = property(_libtrace.libtrace_icmp_un_echo_sequence_get, _libtrace.libtrace_icmp_un_echo_sequence_set)

class libtrace_icmp_un_echoPtr(libtrace_icmp_un_echo):
    def __init__(self, this):
        _swig_setattr(self, libtrace_icmp_un_echo, 'this', this)
        if not hasattr(self,"thisown"): _swig_setattr(self, libtrace_icmp_un_echo, 'thisown', 0)
        _swig_setattr(self, libtrace_icmp_un_echo,self.__class__,libtrace_icmp_un_echo)
_libtrace.libtrace_icmp_un_echo_swigregister(libtrace_icmp_un_echoPtr)

class Packet(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, Packet, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, Packet, name)
    def __init__(self): raise RuntimeError, "No constructor defined"
    def __repr__(self):
        return "<C Packet instance at %s>" % (self.this,)
    __swig_setmethods__["buffer"] = _libtrace.Packet_buffer_set
    __swig_getmethods__["buffer"] = _libtrace.Packet_buffer_get
    if _newclass:buffer = property(_libtrace.Packet_buffer_get, _libtrace.Packet_buffer_set)
    __swig_setmethods__["status"] = _libtrace.Packet_status_set
    __swig_getmethods__["status"] = _libtrace.Packet_status_get
    if _newclass:status = property(_libtrace.Packet_status_get, _libtrace.Packet_status_set)
    __swig_setmethods__["len"] = _libtrace.Packet_len_set
    __swig_getmethods__["len"] = _libtrace.Packet_len_get
    if _newclass:len = property(_libtrace.Packet_len_get, _libtrace.Packet_len_set)
    def get_ip(*args): return _libtrace.Packet_get_ip(*args)
    def get_tcp(*args): return _libtrace.Packet_get_tcp(*args)
    def get_udp(*args): return _libtrace.Packet_get_udp(*args)
    def get_icmp(*args): return _libtrace.Packet_get_icmp(*args)
    def get_seconds(*args): return _libtrace.Packet_get_seconds(*args)

class PacketPtr(Packet):
    def __init__(self, this):
        _swig_setattr(self, Packet, 'this', this)
        if not hasattr(self,"thisown"): _swig_setattr(self, Packet, 'thisown', 0)
        _swig_setattr(self, Packet,self.__class__,Packet)
_libtrace.Packet_swigregister(PacketPtr)

class Trace(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, Trace, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, Trace, name)
    def __repr__(self):
        return "<C libtrace_t instance at %s>" % (self.this,)
    def __init__(self, *args):
        _swig_setattr(self, Trace, 'this', _libtrace.new_Trace(*args))
        _swig_setattr(self, Trace, 'thisown', 1)
    def __del__(self, destroy=_libtrace.delete_Trace):
        try:
            if self.thisown: destroy(self)
        except: pass
    def read_packet(*args): return _libtrace.Trace_read_packet(*args)

class TracePtr(Trace):
    def __init__(self, this):
        _swig_setattr(self, Trace, 'this', this)
        if not hasattr(self,"thisown"): _swig_setattr(self, Trace, 'thisown', 0)
        _swig_setattr(self, Trace,self.__class__,Trace)
_libtrace.Trace_swigregister(TracePtr)


