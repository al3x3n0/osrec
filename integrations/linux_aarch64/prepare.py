"""Pinned original Linux syscall extraction and minimal sequential state contracts.

The reviewed v6.10 definitions are compared with a real 6.10.14 Linux capture;
this does not attest an exact rebuild of the supplied LinuxKit kernel binary.
All code/data needed for replay is copied into the portable checked bundle.
"""
import hashlib
import json
import re
import shutil
import subprocess
from functools import lru_cache
from pathlib import Path

NUMBERS=(172,178,173,174,175,176,177,166,148,166,150,148,166,150,166,148,150,172,166,178)
MASKS=(0,0,0,0,0,0,0,0o77,0,0x1000001ff,0,0,(1<<64)-1,0,0o2,0,0,0,0o22,0)
POINTERS={8:(4,8,12),10:(4,8,12),11:(4,(1<<64)-1,12),13:((1<<64)-1,8,12),15:(4,4,4),16:(4,8,(1<<64)-2)}
ROOTS={'getpid':0,'gettid':0,'getppid':0,'getuid':0,'geteuid':0,'getgid':0,'getegid':0,'getresuid':3,'getresgid':3,'umask':1}
UNCHANGED=(1<<64)-1

def profile_for(capture):
    profile=capture.get('profile','minimal')
    if profile not in ('minimal','credentials','fsgid','group-setters','getgroups','setgroups','setgroups-denied','capabilities','capget','prctl','fsuid','setresuid','uid-setters','credential-setters','fd-dup','file-io','file-positioned','fd-control','close-range','fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):raise ValueError('unsupported Linux capture profile')
    return profile

def recipes(profile='minimal'):
    calls=[dict(number=n,args=list(POINTERS[i]) if i in POINTERS else [MASKS[i],0,0]) for i,n in enumerate(NUMBERS)]
    if profile=='file-setrlimit':return [c for _,c,_ in file_setrlimit_plan()]
    if profile=='file-limits':return [c for _,c,_ in file_limits_plan()]
    if profile=='file-rlimit':return [c for _,c,_ in file_rlimit_plan()]
    if profile=='file-credentials':return [c for _,c,_ in file_credentials_plan()]
    if profile=='file-prctl':return [c for _,c,_ in file_prctl_plan()]
    if profile=='file-capget':return [c for _,c,_ in file_capget_plan()]
    if profile=='file-status':return [c for _,c,_ in file_status_plan()]
    if profile=='file-group-setters':return [c for _,c,_ in file_group_setters_plan()]
    if profile=='file-groups':return [c for _,c,_ in file_groups_plan()]
    if profile=='file-fsuid':return [c for _,c,_ in file_fsuid_plan()]
    if profile=='file-fsgid':return [c for _,c,_ in file_fsgid_plan()]
    if profile=='file-capabilities':return [c for _,c,_ in file_capabilities_plan()]
    if profile=='fchown-capable':return [c for _,c,_ in fchown_capable_plan()]
    if profile=='fchown':return [c for _,c,_ in fchown_plan()]
    if profile=='fchmod':return [c for _,c,_ in fchmod_plan()]
    if profile=='fstat':return [c for _,c,_ in fstat_plan()]
    if profile=='close-range':return [c for _,c,_ in close_range_plan()]
    if profile=='fd-control':return [c for _,c,_ in fd_control_plan()]
    if profile=='file-positioned':return [c for _,c,_ in file_positioned_plan()]
    if profile=='file-io':return [c for _,c,_ in file_io_plan()]
    if profile=='fd-dup':return [call for _,call in fd_dup_plan()]
    if profile=='credential-setters':return [call for _,call,_ in credential_setters_plan()]
    if profile=='uid-setters':return [call for _,call,_ in uid_setters_plan()]
    if profile=='setresuid':return [call for _,call,_ in setresuid_plan()]
    if profile=='fsuid':return [call for _,call,_ in fsuid_plan()]
    if profile=='prctl':return [call for _,call,_ in prctl_plan(recipes('minimal'))]
    if profile=='capget':return [call for _,call in capget_plan()]
    if profile=='capabilities':
        tail=[(158,[0,UNCHANGED,0]),(159,[3,4,0]),(91,[0,8,0]),(159,[2,4,0]),(158,[3,4,0]),
              (91,[0,8,0]),(159,[2,4,0]),(158,[2,4,0]),(91,[0,8,0]),(91,[0,8,0]),(159,[4,4,0]),
              (91,[0,8,0]),(91,[UNCHANGED,8,0]),(91,[28,8,0]),(91,[0,24,0]),(91,[0,UNCHANGED,0]),(91,[0,UNCHANGED-1,0]),
              (91,[0,UNCHANGED,0]),(91,[0,8,0]),(159,[UNCHANGED,UNCHANGED-1,0]),(158,[4,4,0]),(91,[0,8,0]),
              (159,[0,UNCHANGED-1,0]),(158,[4,UNCHANGED,0]),(91,[0,8,0]),(159,[0,UNCHANGED,0]),(91,[0,8,0]),
              (159,[1,28,0]),(91,[0,8,0]),(91,[0,8,0]),(91,[0,8,0]),(91,[0,8,0]),(159,[2,4,0]),
              (91,[0,8,0]),(91,[0,8,0]),(91,[0,8,0]),(158,[1,28,0]),(91,[0,8,0]),(91,[0,8,0]),
              (159,[65537,UNCHANGED-1,0]),(166,[0o77,0,0]),(158,[1,4,0]),(166,[0o22,0,0]),(158,[0,UNCHANGED,0])]
        return calls+[dict(number=n,args=args) for n,args in tail]
    if profile=='setgroups-denied':
        return recipes('setgroups')+[dict(number=n,args=args) for n,args in [(159,[5,4,0]),(159,[65536,UNCHANGED,0]),(159,[0x80000000,UNCHANGED-1,0]),(158,[0,UNCHANGED,0])]]
    if profile=='setgroups':
        tail=[(158,[0,UNCHANGED,0]),(159,[3,4,0]),(158,[0,UNCHANGED-1,0]),(158,[3,4,0]),
              (159,[2,24,0]),(158,[2,4,0]),(159,[4,4,0]),(158,[4,4,0]),(158,[3,4,0]),(158,[4,24,0]),
              (159,[3,28,0]),(158,[0,UNCHANGED,0]),(159,[2,4,0]),(158,[4,4,0]),
              (159,[UNCHANGED,UNCHANGED,0]),(159,[65537,UNCHANGED-1,0]),(159,[0,UNCHANGED,0]),
              (158,[4,UNCHANGED,0]),(158,[0,UNCHANGED-1,0]),(159,[0,UNCHANGED-1,0]),
              (159,[1,28,0]),(158,[1,28,0]),(159,[0x100000002,24,0]),(158,[2,4,0]),
              (159,[3,UNCHANGED,0]),(159,[3,UNCHANGED-1,0]),(159,[3,24,0]),
              (159,[2,4,0]),(158,[2,4,0]),(159,[2,4,0]),(159,[0x1ffffffff,4,0]),
              (166,[0o77,0,0]),(159,[3,4,0]),(158,[3,4,0]),(166,[0o22,0,0]),(158,[0,UNCHANGED,0])]
        return calls+[dict(number=n,args=args) for n,args in tail]
    if profile in ('credentials','fsgid','group-setters','getgroups'):
        tail=[(149,[3000,UNCHANGED,UNCHANGED]),(149,[UNCHANGED]*3),(149,[UNCHANGED,2001,UNCHANGED]),(177,[0,0,0]),(150,[4,8,12]),
              (149,[0x1000007d3,2003,2001]),(176,[0,0,0]),(150,[4,8,12]),(149,[UNCHANGED,2002,UNCHANGED]),(149,[UNCHANGED,2001,UNCHANGED]),
              (177,[0,0,0]),(150,[4,8,12]),(149,[2001,2003,2003]),(150,[4,8,UNCHANGED-1]),(149,[UNCHANGED,2001,UNCHANGED]),
              (150,[4,8,12]),(149,[UNCHANGED]*3),(166,[0o77,0,0]),(174,[0,0,0]),(166,[0o22,0,0]),(176,[0,0,0]),(150,[4,8,12])]
        calls.extend(dict(number=n,args=args) for n,args in tail)
        if profile in ('fsgid','group-setters','getgroups'):
            tail=[(152,[2003,0,0]),(152,[UNCHANGED,0,0]),(150,[4,8,12]),(152,[3000,0,0]),(152,[2003,0,0]),
                  (149,[UNCHANGED,2001,UNCHANGED]),(152,[0x1000007d3,0,0]),(177,[0,0,0]),(152,[UNCHANGED,0,0]),(152,[2001,0,0]),
                  (149,[2003,2003,2001]),(152,[2001,0,0]),(150,[UNCHANGED,8,12]),(152,[2002,0,0]),(149,[UNCHANGED,2003,UNCHANGED]),
                  (152,[2003,0,0]),(152,[UNCHANGED,0,0]),(150,[4,4,4]),(176,[0,0,0]),(150,[4,8,12])]
            calls.extend(dict(number=n,args=args) for n,args in tail)
        if profile in ('group-setters','getgroups'):
            tail=[(144,[2001,0,0]),(150,[4,8,12]),(144,[3000,0,0]),(144,[UNCHANGED,0,0]),(143,[2001,3000,0]),(176,[0,0,0]),
                  (143,[UNCHANGED,UNCHANGED,0]),(143,[0x1000007d1,2003,0]),(150,[4,UNCHANGED,12]),(144,[2003,0,0]),(143,[UNCHANGED,2001,0]),
                  (143,[2003,UNCHANGED,0]),(144,[2003,0,0]),(144,[2001,0,0]),(143,[UNCHANGED,2003,0]),(144,[2003,0,0]),
                  (149,[UNCHANGED,UNCHANGED,2001]),(144,[2003,0,0]),(143,[UNCHANGED,2003,0]),(152,[2001,0,0]),(144,[0x1000007d1,0,0]),
                  (177,[0,0,0]),(143,[UNCHANGED,0x1ffffffff,0]),(144,[0x1ffffffff,0,0]),(143,[2001,2001,0]),(144,[2003,0,0]),
                  (152,[2003,0,0]),(150,[4,8,12]),(166,[0o77,0,0]),(172,[0,0,0]),(166,[0o22,0,0]),(150,[4,8,12])]
            calls.extend(dict(number=n,args=args) for n,args in tail)
        if profile=='getgroups':
            tail=[(158,[0,UNCHANGED,0]),(158,[3,4,0]),(158,[2,4,0]),(158,[UNCHANGED,UNCHANGED,0]),(158,[4,UNCHANGED,0]),
                  (158,[3,28,0]),(158,[0,UNCHANGED-1,0]),(158,[0x100000003,4,0]),(158,[0x1ffffffff,4,0]),(158,[4,4,0]),
                  (158,[3,UNCHANGED-1,0]),(144,[2001,0,0]),(158,[3,24,0]),(158,[8,0,0]),(143,[UNCHANGED,UNCHANGED,0]),
                  (158,[0x100000000,UNCHANGED,0]),(158,[3,4,0]),(158,[0,UNCHANGED,0])]
            calls.extend(dict(number=n,args=args) for n,args in tail)
    elif profile!='minimal':raise ValueError('unsupported Linux capture profile')
    return calls

BOOT=1<<22
GID=1<<6
PCAP=1<<8
ALL=BOOT|GID|PCAP

def prctl_plan(base):
    out=[(str(i),dict(number=c['number'],args=c['args']+[0,0]),None) for i,c in enumerate(base)]
    def add(name,number,args,data=None):out.append((name,dict(number=number,args=args+[0]*(5-len(args))),data))
    def pr(name,*args):add(name,167,list(args))
    def caps(name,e=ALL,p=ALL,i=0):add(name,91,[0,8],(e,p,i))
    def get(name):add(name,90,[0,8])
    pr('bounding_initial',23,6)
    pr('bounding_invalid',23,41)
    pr('bounding_unsigned',23,(1<<64)-1)
    pr('drop_invalid_privileged',24,41)
    get('initial_caps')
    pr('raise_without_inheritable',47,2,6)
    caps('inherit_gid',i=GID)
    pr('raise_gid',47,2,6)
    pr('ambient_gid_set',47,1,6)
    get('inherited_caps')
    pr('ambient_unknown',47,9,6)
    pr('ambient_invalid_cap',47,1,41)
    pr('ambient_arg4',47,1,6,1)
    pr('ambient_arg5',47,1,6,0,1)
    pr('clear_arg3',47,4,1)
    pr('clear_arg4',47,4,0,1)
    pr('clear_arg5',47,4,0,0,1)
    pr('lower_gid',47,3,6)
    pr('ambient_gid_clear',47,1,6)
    pr('lower_gid_again',47,3,6)
    pr('raise_gid_again',47,2,6)
    add('groups_three',159,[3,4],[5009,5001,5005])
    pr('drop_gid',24,6)
    pr('bounding_gid_dropped',23,6)
    get('caps_after_bounding_drop')
    caps('retain_inheritable_outside_bounding',i=GID)
    pr('ambient_after_bounding_drop',47,1,6)
    caps('remove_inheritable_gid')
    pr('raise_gid_after_inheritable_drop',47,2,6)
    caps('cannot_restore_inheritable_gid',i=GID)
    add('groups_after_bounding_drop',159,[2,4],[6003,6001])
    add('read_groups',158,[2,4])
    pr('drop_uid',24,7)
    caps('cannot_add_inheritable_uid',i=1<<7)
    caps('drop_effective_setpcap',e=BOOT|GID)
    pr('drop_without_effective_setpcap',24,7)
    pr('drop_invalid_unprivileged',24,41)
    pr('securebits_without_setpcap',28,64)
    caps('regain_effective_setpcap')
    pr('keepcaps_invalid',8,2)
    pr('keepcaps_on',8,1)
    pr('keepcaps_read',7)
    pr('securebits_keepcaps',27)
    pr('keepcaps_off',8,0)
    caps('inherit_setpcap',i=PCAP)
    pr('raise_setpcap',47,2,8)
    pr('forbid_ambient_raise',28,64)
    pr('lower_setpcap',47,3,8)
    pr('securebits_reject_raise',47,2,8)
    pr('securebits_read',27)
    pr('allow_ambient_raise',28,0)
    pr('raise_setpcap_again',47,2,8)
    pr('clear_all',47,4)
    pr('clear_all_again',47,4)
    pr('lock_securebits',28,240)
    pr('unlock_rejected',28,0)
    pr('change_locked_rejected',28,176)
    pr('unsupported_securebits',28,496)
    pr('locked_securebits_read',27)
    pr('locked_keepcaps_read',7)
    pr('locked_keepcaps_rejected',8,0)
    pr('locked_keepcaps_invalid',8,2)
    caps('drop_permitted_setpcap',e=BOOT|GID,p=BOOT|GID,i=PCAP)
    get('caps_after_permitted_drop')
    caps('cannot_regain_permitted_setpcap',i=PCAP)
    pr('bounding_drop_after_permitted_drop',24,8)
    pr('locked_raise_after_permitted_drop',47,2,8)
    add('empty_groups',159,[0,(1<<64)-2])
    add('mask_077',166,[0o77])
    add('empty_query',158,[0,(1<<64)-1])
    add('mask_022',166,[0o22])
    get('final_caps')
    return out

FS_CAPS=sum(1<<n for n in (0,1,2,3,4,9,27,32))
FS_INITIAL=ALL|(1<<7)|FS_CAPS
FS_INHERIT=(1<<0)|(1<<32)
FS_PERMITTED=FS_INITIAL&~FS_INHERIT

def fsuid_plan():
    """Named original-kernel FSUID/security transitions and concrete inputs."""
    out=[(str(i),dict(number=c['number'],args=c['args']+[0,0]),None) for i,c in enumerate(recipes('minimal'))]
    def add(name,number,args,data=None):out.append((name,dict(number=number,args=args+[0]*(5-len(args))),data))
    def fs(name,uid):add(name,151,[uid])
    def get(name):add(name,90,[0,8])
    def caps(name,e,p=FS_INITIAL,i=FS_INHERIT):add(name,91,[0,8],(e,p,i))
    def pr(name,*args):add(name,167,list(args))
    fs('initial_probe',UNCHANGED)
    get('initial_caps')
    fs('drop_fs_caps',1001)
    get('caps_dropped')
    fs('same_fsuid',1001)
    fs('restore_fs_caps',0)
    get('caps_restored')
    fs('privileged_foreign_uid',9001)
    add('real_uid_unchanged',174,[])
    add('effective_uid_unchanged',175,[])
    fs('restore_from_foreign',0)
    caps('drop_effective_setuid',FS_INITIAL&~(1<<7))
    pr('raise_ambient_chown',47,2,0)
    pr('raise_ambient_mac',47,2,32)
    fs('drop_with_ambient',1001)
    get('caps_with_ambient')
    fs('foreign_uid_denied',9001)
    fs('same_nonroot',1001)
    fs('invalid_probe',UNCHANGED)
    fs('restore_without_setuid',0)
    get('selective_restore')
    caps('same_capabilities',FS_INITIAL&~(1<<7))
    pr('disable_fs_fixup',28,4)
    fs('suppressed_drop',1001)
    get('caps_drop_suppressed')
    fs('denied_with_fixup_suppressed',9001)
    fs('suppressed_restore',0)
    pr('enable_fs_fixup',28,0)
    fs('drop_after_enabling',1001)
    get('caps_fixup_enabled')
    caps('remove_permitted_fs_bits',ALL,p=FS_PERMITTED)
    fs('restore_remaining_permitted',0)
    get('bounded_restore')
    caps('cannot_regain_permitted',FS_INITIAL&~(1<<7))
    fs('truncated_nonroot',0x1000003e9)
    fs('truncated_invalid',0x1ffffffff)
    fs('truncated_root',0x100000000)
    add('replace_groups',159,[3,4],[6007,6001,6003])
    add('read_groups',158,[3,4])
    caps('drop_nonfilesystem_effective',BOOT|PCAP,p=FS_PERMITTED)
    fs('drop_after_effective_removal',1001)
    add('groups_denied_nonroot',159,[0,UNCHANGED-1])
    fs('selective_effective_regain',0)
    add('groups_still_denied_root',159,[0,UNCHANGED-1])
    get('caps_nonfilesystem_not_regained')
    pr('lock_fs_fixup',28,12)
    fs('locked_suppressed_drop',1001)
    fs('locked_suppressed_restore',0)
    pr('unlock_fixup_denied',28,0)
    caps('drop_all_effective_except_boot',BOOT,p=FS_PERMITTED)
    fs('locked_drop_after_capset',1001)
    fs('foreign_denied_without_effective',9001)
    fs('locked_restore_after_capset',0)
    get('caps_locked_no_regain')
    add('user_ids_unchanged',148,[4,8,12])
    add('groups_denied_final',159,[0,UNCHANGED-1])
    add('groups_preserved_final',158,[3,4])
    add('mask_077',166,[0o77])
    fs('final_probe',UNCHANGED)
    add('mask_022',166,[0o22])
    fs('same_root',0)
    get('final_caps')
    pr('final_securebits',27)
    add('final_group_count',158,[0,UNCHANGED])
    return out

def setresuid_plan():
    """Real/effective/saved UID transitions with accounting and capability state."""
    out=[(str(i),dict(number=c['number'],args=c['args']+[0,0]),None) for i,c in enumerate(recipes('minimal'))]
    def add(name,n,args,data=None):out.append((name,dict(number=n,args=args+[0]*(5-len(args))),data))
    def uid(name,r=UNCHANGED,e=UNCHANGED,s=UNCHANGED):add(name,147,[r,e,s])
    def caps(name,e=FS_INITIAL,p=FS_INITIAL,i=FS_INHERIT):add(name,91,[0,8],(e,p,i))
    def get(name):add(name,90,[0,8])
    def pr(name,*args):add(name,167,list(args))
    uid('all_sentinels')
    uid('same_ids',1001,0,0)
    caps('inherit_fs_bits')
    pr('ambient_chown',47,2,0)
    pr('ambient_mac',47,2,32)
    uid('drop_effective_root',e=1001)
    get('caps_effective_dropped')
    add('groups_denied_nonroot',159,[0,UNCHANGED-1])
    uid('foreign_uid_denied',r=9001)
    uid('restore_saved_root',e=0)
    get('caps_root_restored')
    add('replace_groups',159,[3,4],[6007,6001,6003])
    add('filesystem_diverge',151,[1001])
    uid('sentinels_preserve_fsuid')
    uid('explicit_euid_repairs_fsuid',e=0)
    get('caps_fs_repair_is_res_fixup')
    caps('drop_effective_setuid',FS_INITIAL&~(1<<7))
    uid('foreign_effective_denied',e=9001)
    uid('foreign_saved_denied',s=9001)
    uid('real_to_saved_root',r=0)
    add('real_uid_changed',174,[])
    uid('restore_real_with_permitted',r=1001)
    caps('regain_effective_setuid')
    uid('real_to_foreign_privileged',r=9001)
    uid('saved_to_foreign_privileged',s=9002)
    add('read_foreign_ids',148,[4,8,12])
    uid('reset_root_identity',1001,0,0)
    pr('keepcaps_on',8,1)
    uid('drop_all_root_ids_keepcaps',1001,1001,1001)
    get('kept_permitted_cleared_effective_ambient')
    uid('cannot_restore_root_without_effective',e=0)
    add('groups_denied_keepcaps',159,[0,UNCHANGED-1])
    caps('regain_effective_from_kept_permitted')
    uid('restore_root_with_capability',1001,0,0)
    pr('keepcaps_off',8,0)
    pr('disable_uid_fixup',28,4)
    pr('raise_ambient_again',47,2,32)
    uid('drop_all_with_suppression',9001,9001,9002)
    get('suppressed_caps_preserved')
    add('groups_allowed_suppressed',159,[2,4],[7003,7001])
    uid('restore_suppressed_root',1001,0,0)
    pr('enable_uid_fixup',28,0)
    uid('truncated_real_uid',0x100002329)
    uid('truncated_sentinel',0x1ffffffff,0x1ffffffff,0x1ffffffff)
    uid('truncated_effective_nonroot',e=0x1000003e9)
    add('effective_uid_changed',175,[])
    uid('restore_truncated_root',e=0x100000000)
    uid('restore_initial_real_uid',r=1001)
    caps('remove_permitted_fs_bits',FS_PERMITTED,p=FS_PERMITTED)
    uid('drop_before_selective_root_regain',e=1001)
    uid('regain_only_remaining_permitted',e=0)
    get('selective_root_caps')
    pr('lock_uid_fixup',28,12)
    caps('retain_boot_only',BOOT,p=FS_PERMITTED)
    uid('locked_drop_without_cap_setuid',1001,1001,1001)
    uid('locked_foreign_denied',r=9001)
    uid('locked_root_denied',e=0)
    uid('locked_noop',1001,1001,1001)
    add('read_final_ids',148,[4,8,12])
    add('final_groups',158,[2,4])
    get('final_caps')
    pr('final_securebits',27)
    return out

def uid_setters_plan():
    """Named ID/RE/RES/FS transitions, including aborted inactive UID edits."""
    out=[(str(i),dict(number=c['number'],args=c['args']+[0,0]),None) for i,c in enumerate(recipes('minimal'))]
    def add(name,n,args,data=None):out.append((name,dict(number=n,args=args+[0]*(5-len(args))),data))
    def uid(name,value):add(name,146,[value])
    def re(name,r=UNCHANGED,e=UNCHANGED):add(name,145,[r,e])
    def res(name,r=UNCHANGED,e=UNCHANGED,s=UNCHANGED):add(name,147,[r,e,s])
    def caps(name,e=FS_INITIAL,p=FS_INITIAL,i=FS_INHERIT):add(name,91,[0,8],(e,p,i))
    def get(name):add(name,90,[0,8])
    def pr(name,*args):add(name,167,list(args))
    uid('invalid_setuid',UNCHANGED)
    uid('truncated_invalid_setuid',0x1ffffffff)
    uid('privileged_root_setuid',0)
    uid('same_root_publishes',0)
    res('reset_initial_ids',1001,0,0)
    caps('inherit_fs_bits')
    pr('ambient_chown',47,2,0)
    pr('ambient_mac',47,2,32)
    caps('drop_effective_setuid',FS_INITIAL&~(1<<7))
    uid('unprivileged_real_setuid',1001)
    get('caps_after_effective_drop')
    uid('foreign_setuid_denied',9001)
    add('partial_uid_output',148,[4,UNCHANGED,12])
    uid('saved_root_setuid',0)
    caps('drop_setuid_after_root_regain',FS_INITIAL&~(1<<7))
    uid('same_unprivileged_setuid_publishes',0)
    add('filesystem_diverge',151,[1001])
    re('sentinels_publish_and_repair_fsuid')
    re('same_real_publishes',1001)
    re('effective_to_real_preserves_saved',e=1001)
    add('saved_root_preserved',148,[4,8,12])
    re('foreign_real_denied',9001)
    re('foreign_effective_denied',e=9002)
    re('restore_saved_root',e=0)
    res('install_foreign_saved',s=9002)
    caps('drop_setuid_for_saved_check',FS_INITIAL&~(1<<7))
    re('saved_only_real_denied',9002)
    re('real_to_effective_root',0)
    res('res_foreign_real_denied',1001,0,0)
    caps('regain_effective_setuid')
    res('reset_for_partial_abort',1001,0,0)
    res('install_nonroot_effective',e=9001)
    re('partial_real_then_effective_denied',9001,9002)
    add('active_real_after_abort',174,[])
    add('active_effective_after_abort',175,[])
    re('restore_after_partial_abort',e=0)
    re('swap_real_root_to_effective',0,1001)
    re('swap_root_back',1001,0)
    re('same_ids_publish',1001,0)
    re('truncated_sentinels_publish',0x1ffffffff,0x1ffffffff)
    re('truncated_foreign_real',0x100002329,0x100000000)
    res('reset_after_truncated_real',1001,0,0)
    re('truncated_effective_to_real',e=0x1000003e9)
    re('truncated_root_restore',e=0x100000000)
    pr('keepcaps_on',8,1)
    uid('privileged_nonroot_setuid_keepcaps',9002)
    get('kept_permitted_cleared_effective_ambient')
    uid('root_setuid_denied_without_effective',0)
    add('groups_denied_keepcaps',159,[0,UNCHANGED-1])
    caps('regain_kept_effective')
    uid('privileged_restore_all_root',0)
    pr('keepcaps_off',8,0)
    res('reset_before_suppression',1001,0,0)
    pr('disable_uid_fixup',28,4)
    pr('raise_ambient_mac_again',47,2,32)
    uid('suppressed_setuid_all_nonroot',9001)
    re('suppressed_real_and_effective',9002,1001)
    add('groups_allowed_suppressed',159,[3,4],[7007,7001,7003])
    add('suppressed_filesystem_diverge',151,[0])
    re('suppressed_sentinels_repair_fsuid')
    pr('lock_uid_fixup',28,12)
    caps('retain_boot_only',BOOT)
    uid('locked_setuid_saved',1001)
    uid('locked_setuid_real',9002)
    re('locked_saved_only_real_denied',1001)
    re('locked_effective_saved_allowed',e=1001)
    re('locked_partial_abort',1001,9001)
    re('locked_sentinels_overwrite_abort')
    uid('locked_root_setuid_denied',0)
    add('aliased_final_user_ids',148,[4,4,4])
    add('final_groups',158,[3,4])
    get('final_caps')
    pr('final_securebits',27)
    return out

def credential_setters_plan():
    """Combined UID/GID setters, supplementary lists and live capability admission."""
    out=[(str(i),dict(number=c['number'],args=c['args']+[0,0]),None) for i,c in enumerate(recipes('minimal'))]
    def add(name,n,args,data=None):out.append((name,dict(number=n,args=args+[0]*(5-len(args))),data))
    def gid(name,value):add(name,144,[value])
    def re(name,r=UNCHANGED,e=UNCHANGED):add(name,143,[r,e])
    def res(name,r=UNCHANGED,e=UNCHANGED,s=UNCHANGED):add(name,149,[r,e,s])
    def fs(name,value):add(name,152,[value])
    def uid(name,value):add(name,146,[value])
    def ures(name,r=UNCHANGED,e=UNCHANGED,s=UNCHANGED):add(name,147,[r,e,s])
    def ure(name,r=UNCHANGED,e=UNCHANGED):add(name,145,[r,e])
    def caps(name,e=FS_INITIAL,p=FS_INITIAL,i=FS_INHERIT|GID):add(name,91,[0,8],(e,p,i))
    def get(name):add(name,90,[0,8])
    def pr(name,*args):add(name,167,list(args))
    gid('invalid_setgid',UNCHANGED)
    gid('privileged_all_groups',4001)
    gid('same_gid_publishes',4001)
    add('query_privileged_groups',150,[4,8,12])
    res('reset_initial_groups',2001,2002,2003)
    fs('privileged_foreign_fsgid',9001)
    fs('fsgid_probe',UNCHANGED)
    res('sentinels_preserve_fsgid')
    res('explicit_egid_repairs_fsgid',e=2002)
    re('privileged_foreign_regid',9001,9002)
    add('effective_group_query',177,[])
    add('replace_groups_privileged',159,[3,4],[5009,5001,5005])
    uid('uid_copy_preserves_group_ids',0)
    res('reset_before_capability_drop',2001,2002,2003)
    caps('drop_effective_setgid',FS_INITIAL&~GID)
    pr('raise_ambient_setgid',47,2,6)
    re('saved_only_real_gid_denied',2003)
    fs('foreign_fsgid_denied',9001)
    res('foreign_resgid_denied',r=9001)
    re('partial_real_gid_then_effective_denied',2002,9002)
    add('query_active_after_abort',150,[4,8,12])
    add('real_group_after_abort',176,[])
    gid('unprivileged_saved_gid',2003)
    re('real_to_effective_gid',2003)
    re('dropped_old_real_denied',e=2001)
    caps('regain_effective_setgid')
    re('foreign_groups_after_regain',9001,9002)
    get('gid_changes_preserve_caps_and_ambient')
    res('reset_after_regain',2001,2002,2003)
    gid('all_root_groups',0)
    add('scalar_changes_preserve_list',158,[3,4])
    ures('restore_initial_user',1001,0,0)
    ure('drop_effective_uid',e=1001)
    gid('setgid_denied_after_uid_drop',9001)
    res('setresgid_denied_after_uid_drop',r=9001)
    add('setgroups_denied_after_uid_drop',159,[0,UNCHANGED-1])
    gid('same_root_gid_without_capability',0)
    fs('uid_value_does_not_authorize_gid',1001)
    uid('restore_saved_root_uid',0)
    res('foreign_groups_after_uid_restore',0,1001,2003)
    add('replace_list_after_uid_restore',159,[2,4],[6003,6001])
    fs('truncated_fsgid',0x1000007d3)
    res('sentinels_keep_divergent_fsgid')
    re('sentinels_publish_repair_fsgid')
    add('partial_group_output',150,[4,UNCHANGED,12])
    gid('truncated_root_gid',0x100000000)
    gid('truncated_invalid_gid',0x1ffffffff)
    re('truncated_regid',0x1000007d1,0x1000007d3)
    fs('final_fsgid_probe',UNCHANGED)
    add('drop_filesystem_uid_caps',151,[1001])
    add('list_allowed_after_fsuid_drop',159,[1,4],[7001])
    gid('foreign_gid_after_fsuid_drop',9002)
    ures('uid_repair_preserves_groups',e=0)
    res('reset_before_permitted_drop',2001,2002,2003)
    caps('remove_permitted_setgid',FS_INITIAL&~GID,p=FS_INITIAL&~GID)
    re('foreign_regid_after_permitted_drop',9001,1001)
    add('list_denied_after_permitted_drop',159,[0,UNCHANGED-1])
    caps('cannot_restore_permitted_setgid')
    ures('drop_uid_after_permitted_drop',e=1001)
    ures('restore_uid_only_remaining_permitted',e=0)
    add('list_still_denied_after_root_regain',159,[0,UNCHANGED-1])
    fs('fsgid_still_denied_after_root_regain',9001)
    get('root_regain_does_not_restore_setgid')
    pr('disable_uid_fixup',28,4)
    ure('suppressed_uid_swap',0,1001)
    uid('suppressed_all_user_ids',9001)
    re('group_copy_preserves_user_accounting')
    ure('move_final_accounting_user',9002,9002)
    res('same_resgid_no_publication',2001,2002,2003)
    pr('lock_uid_fixup',28,12)
    caps('retain_boot_only',BOOT,p=FS_INITIAL&~GID)
    re('final_partial_gid_abort',2002,9001)
    ure('uid_copy_overwrites_group_abort')
    add('aliased_final_group_ids',150,[4,4,4])
    add('final_user_ids',148,[4,8,12])
    add('final_supplementary_list',158,[1,4])
    get('final_caps')
    pr('final_securebits',27)
    return out

def capget_plan():
    """Base-call IDs preserve existing capture inputs; query IDs are explicit."""
    queries={20:['initial'],23:['dropped'],26:['regained'],30:['legacy'],32:['unknown_null','unknown_output','null_negative_pid','header_tail_null','header_tail_pid_fault'],
             41:['negative_pid','missing_pid','guard_output','partial_output','null_header','bad_header','bad_output'],
             42:['inheritable'],44:['aliased_output'],48:['single_group'],52:['permitted_dropped'],58:['inheritable_dropped']}
    args={'header_tail_null':[28,UNCHANGED,0],'header_tail_pid_fault':[28,8,0],'guard_output':[0,32,0],'partial_output':[0,24,0],
          'null_header':[UNCHANGED,8,0],'bad_header':[UNCHANGED-1,8,0],'bad_output':[0,UNCHANGED-1,0],'aliased_output':[0,0,0]}
    nulls={'unknown_null','null_negative_pid'}
    out=[]
    for i,call in enumerate(recipes('capabilities')):
        for name in queries.get(i,[]):out.append((name,dict(number=90,args=args.get(name,[0,UNCHANGED if name in nulls else 8,0]))))
        out.append((i,call))
    return out

@lru_cache(maxsize=32)
def _file_input_rows(profile):
    """Keep only immutable recipe inputs; callers receive independent buffers."""
    plans={'file-io':file_io_plan,'file-positioned':file_positioned_plan,
           'fd-control':fd_control_plan,'close-range':close_range_plan,
           'fstat':fstat_plan,'fchmod':fchmod_plan,'fchown':fchown_plan,
           'fchown-capable':fchown_capable_plan,'file-capabilities':file_capabilities_plan,
           'file-fsgid':file_fsgid_plan,'file-fsuid':file_fsuid_plan,
           'file-groups':file_groups_plan,'file-group-setters':file_group_setters_plan,'file-status':file_status_plan,'file-capget':file_capget_plan,'file-prctl':file_prctl_plan,'file-credentials':file_credentials_plan,'file-rlimit':file_rlimit_plan,'file-limits':file_limits_plan,'file-setrlimit':file_setrlimit_plan}
    return tuple(None if data is None else tuple(data) for _,_,data in plans[profile]())

def input_words(profile,ordinal):
    words=[0xa5a50000+j for j in range(8)]
    if profile in ('file-io','file-positioned','fd-control','close-range','fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):
        data=_file_input_rows(profile)[ordinal]
        if data is not None:words=list(data)
        return words
    if profile in ('fsuid','setresuid','uid-setters','credential-setters'):
        _,call,data=(credential_setters_plan() if profile=='credential-setters' else uid_setters_plan() if profile=='uid-setters' else setresuid_plan() if profile=='setresuid' else fsuid_plan())[ordinal]
        if call['number']==91:
            e,p,i=data;words=[0x20080522,0,e&0xffffffff,p&0xffffffff,i&0xffffffff,e>>32,p>>32,i>>32]
        elif call['number']==90:words[:2]=[0x20080522,0]
        elif call['number']==159 and data:words[1:1+len(data)]=data
        return words
    if profile=='prctl':
        _,call,data=prctl_plan(recipes('minimal'))[ordinal]
        if call['number']==91:
            e,p,i=data;words=[0x20080522,0,e,p,i,0,0,0]
        elif call['number']==90:words[:2]=[0x20080522,0]
        elif call['number']==159 and data:words[1:1+len(data)]=data
        return words
    if profile=='capget':
        key,call=capget_plan()[ordinal]
        if type(key) is int:return input_words('capabilities',key)
        words[0]=0 if key in ('unknown_null','unknown_output') else 0x19980330 if key=='legacy' else 0x20071026 if key=='regained' else 0x20080522
        words[1]=0xffffffff if key in ('null_negative_pid','negative_pid') else 0x7fffffff if key=='missing_pid' else 1 if key=='regained' else 0
        if key.startswith('header_tail'):words[7]=0x20080522
        return words
    if profile=='capabilities':
        groups={21:(1,[5009,5001,5005]),23:(1,[6003,6001]),26:(1,[6003,6001]),30:(1,[7007,7001,7003,7001]),47:(7,[9001]),52:(1,[8003,8001])}
        if ordinal in groups:
            at,values=groups[ordinal];words[at:at+len(values)]=values
        if recipes(profile)[ordinal]['number']==91:
            boot=1<<22;gid=1<<6;uid=1<<7;v1=0x19980330;v2=0x20071026;v3=0x20080522
            values={22:(boot,boot|gid,0),25:(boot|gid,boot|gid,0),28:(boot|gid,boot|gid,0),29:(boot|gid,boot,0),
                    38:(boot,boot|gid,0),41:(boot|gid,boot|gid,gid),44:(boot,boot|gid,gid),46:(boot|gid,boot|gid,gid),
                    48:(boot|gid,boot|gid|uid,gid),49:(boot|gid,boot|gid,gid|uid),50:(boot|gid,boot|gid,gid),
                    51:(boot,boot,gid),53:(boot|gid,boot|gid,gid),54:(boot|gid,boot,gid),55:(boot,boot,gid),57:(boot,boot,0),58:(boot,boot,gid)}
            effective,permitted,inheritable=values.get(ordinal,(boot|gid,boot|gid,0))
            words=[v1 if ordinal==44 else v2 if ordinal==46 else 0 if ordinal==31 else v3,2 if ordinal==37 else 1 if ordinal==38 else 0,effective,permitted,inheritable,0,0,0]
            if ordinal==33:words[7]=v3
            if ordinal==50:words[5:]=[0x80000000]*3
    if profile in ('setgroups','setgroups-denied'):
        inputs={21:(1,[5009,5001,5005]),24:(6,[6003,6003]),26:(1,[7007,7001,7003,7001]),
                30:(7,[8001]),32:(1,[8003,0xffffffff]),40:(7,[9001]),42:(6,[0,0xfffffffe]),
                46:(6,[42,41]),47:(1,[4003,4001]),49:(1,[4001,4003]),52:(1,[4007,4001,4003])}
        if ordinal in inputs:
            at,values=inputs[ordinal];words[at:at+len(values)]=values
    return words

def application_source(profile,port):
    """Generate a libc-free C witness from recipes and reviewed argument kinds."""
    calls=recipes(profile);count=len(calls);width=max(len(c['args']) for c in calls)
    if not 1<=width<=6:raise ValueError('Linux witness argument width is unsupported')
    roots={r['number']:r for r in port['roots']}
    integer=lambda v:'UINT64_C('+str(v)+')'
    rows=lambda values:'{'+','.join(values)+'}'
    text='#include "osrec_application.h"\n'
    text+='static const uint64_t numbers['+str(count)+']='+rows([str(c['number']) for c in calls])+';\n'
    for c in calls:
        if c['number'] not in roots:raise ValueError('Linux witness syscall has no reviewed route')
    text+='static const uint64_t values['+str(count)+']['+str(width)+']={\n'+',\n'.join(rows([integer(v) for v in c['args']]) for c in calls)+'\n};\n'
    kind=lambda c,j:{'buffer':1,'iovec':2}.get(roots[c['number']]['arguments'][j],0) if j<len(roots[c['number']]['arguments']) else 0
    text+='static const uint8_t buffers['+str(count)+']['+str(width)+']={\n'+',\n'.join(rows([str(kind(c,j)) for j in range(width)]) for c in calls)+'\n};\n'
    text+='static const uint32_t inputs['+str(count)+'][8]={\n'+',\n'.join(rows([str(v)+'u' for v in input_words(profile,i)]) for i in range(count))+'\n};\n'
    text+='''/* The witness ends at a page boundary; native setup protects the next page. */
_Alignas(4096) uint32_t app_guard_storage[2048];
extern uint32_t app_words[8];
__asm__(".global app_words\\n.type app_words,%object\\n.set app_words,app_guard_storage+4064\\n.size app_words,32\\n");
'''
    text+='uint64_t app_returns['+str(count)+'],app_count;\n'
    text+='''#ifdef OSREC_NATIVE_CAPTURE
#ifdef OSREC_LINUX_SETGROUPS_PROFILE
void osrec_native_record_input(unsigned,uint64_t,const uint64_t *,const uint32_t *);
#else
void osrec_native_record(unsigned,uint64_t,const uint64_t *);
#endif
#endif
void osrec_application_main(void)
{
'''
    text+='    for(unsigned i=0;i<'+str(count)+';++i){\n'
    text+='''        for(unsigned j=0;j<8;++j)app_words[j]=inputs[i][j];
        uint64_t args[6]={0};
'''
    text+='        for(unsigned j=0;j<'+str(width)+';++j){uint64_t value=values[i][j];\n'
    text+='''            if(buffers[i][j])value=value==UINT64_MAX ? 0 : value==UINT64_MAX-1 ? 1 : (uintptr_t)app_words+value;
            args[j]=value;
        }
#ifdef OSREC_NATIVE_CAPTURE
#ifdef OSREC_LINUX_SETGROUPS_PROFILE
        uint32_t before[8];for(unsigned j=0;j<8;++j)before[j]=app_words[j];
#endif
#endif
        /* An iovec's segment bases are app_words offsets: addresses for the call, offsets again after it. */
        unsigned relocated=0,iovec_at=0;
        for(unsigned j=0;j+1<sizeof buffers[0];++j)if(buffers[i][j]==2 && values[i][j]<32){iovec_at=(unsigned)values[i][j];
            for(uint64_t k=0;k<values[i][j+1] && iovec_at+16*k+16<=32;++k){uint64_t *entry=(uint64_t *)((unsigned char *)app_words+iovec_at+16*k);*entry+=(uintptr_t)app_words;++relocated;}}
        app_returns[i]=(uint64_t)(i<8 ? osrec_app_syscall_prefix(numbers[i],args[0],args[1],args[2],args[3],args[4],args[5]) : osrec_app_syscall(numbers[i],args[0],args[1],args[2],args[3],args[4],args[5]));
        for(unsigned k=0;k<relocated;++k){uint64_t *entry=(uint64_t *)((unsigned char *)app_words+iovec_at+16*k);*entry-=(uintptr_t)app_words;}
        ++app_count;
#ifdef OSREC_NATIVE_CAPTURE
#ifdef OSREC_LINUX_SETGROUPS_PROFILE
        osrec_native_record_input(i,numbers[i],args,before);
#else
        osrec_native_record(i,numbers[i],args);
#endif
#endif
    }
}
'''
    if not any(kind(c,j)==2 for c in calls for j in range(width)):
        # Without an iovec argument the witness has nothing to relocate (and keeps its prior text).
        text=text.replace('''        /* An iovec's segment bases are app_words offsets: addresses for the call, offsets again after it. */
        unsigned relocated=0,iovec_at=0;
        for(unsigned j=0;j+1<sizeof buffers[0];++j)if(buffers[i][j]==2 && values[i][j]<32){iovec_at=(unsigned)values[i][j];
            for(uint64_t k=0;k<values[i][j+1] && iovec_at+16*k+16<=32;++k){uint64_t *entry=(uint64_t *)((unsigned char *)app_words+iovec_at+16*k);*entry+=(uintptr_t)app_words;++relocated;}}
''','').replace('''        for(unsigned k=0;k<relocated;++k){uint64_t *entry=(uint64_t *)((unsigned char *)app_words+iovec_at+16*k);*entry-=(uintptr_t)app_words;}
''','')
    if profile in ('fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):
        text=text.replace('uint64_t app_returns[', 'uint64_t stat_digest;\n_Alignas(4096) uint32_t stat_guard_storage[2048];\nextern uint32_t stat_words[32];\n__asm__(".global stat_words\\n.type stat_words,%object\\n.set stat_words,stat_guard_storage+3968\\n.size stat_words,128\\n");\nuint64_t app_returns[',1)
        text=text.replace('        uint64_t args[6]={0};','        for(unsigned j=0;j<32;++j)stat_words[j]=0x5a5a0000u+j;\n        uint64_t args[6]={0};')
        text=text.replace('(uintptr_t)app_words+value','(numbers[i]==80 ? (uintptr_t)stat_words : (uintptr_t)app_words)+value')
        text=text.replace('        ++app_count;','        if(numbers[i]==80 && !app_returns[i]){for(unsigned j=18;j<30;++j)stat_words[j]=0; /* Application discards clock fields. */ for(unsigned j=0;j<32;++j)stat_digest=stat_digest*UINT64_C(1099511628211)^stat_words[j];}\n        ++app_count;')
    if profile in ('file-io','file-positioned','fd-control','close-range','fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):text=text.replace('#ifdef OSREC_LINUX_SETGROUPS_PROFILE','#if defined(OSREC_LINUX_SETGROUPS_PROFILE) || defined(OSREC_LINUX_FILE_IO_PROFILE)')
    return text

def setgroups_projection(capture):
    """Independent value/lifetime decoder; pool counts are model bookkeeping."""
    initial=capture['initial'];profile=profile_for(capture);denied=profile=='setgroups-denied';mask=initial['umask'];active=0;generation=0;epochs=[0,0];links=[0,0]
    cap_pool=[list(initial['capabilities']) for _ in range(2)] if profile in ('capabilities','capget','prctl','fsuid','setresuid','uid-setters','credential-setters') else None
    pools=[dict(usage=1,ngroups=3,gid=initial['groups']+[0]),dict(usage=0,ngroups=0,gid=[0]*4)]
    secure_pool=[initial['securebits']]*2 if profile in ('prctl','fsuid','setresuid','uid-setters','credential-setters') else None
    fsuid_pool=[initial['fsuid']]*2 if profile in ('fsuid','setresuid','uid-setters','credential-setters') else None
    uid_pool=[initial['uids'][:] for _ in range(2)] if profile in ('setresuid','uid-setters','credential-setters') else None
    user_links=[[0,0],[0,0]] if profile in ('uid-setters','credential-setters') else None
    scalar=[[*initial['gids'],initial['gids'][1]] for _ in range(2)]
    def snapshot():return dict(gids=scalar[active][:3],fsgid=scalar[active][3],pool=[v[:] for v in scalar],active=active,generation=generation,epochs=epochs[:],credential_groups=links[:],group_pool=[dict(usage=p['usage'],ngroups=p['ngroups'],gid=p['gid'][:]) for p in pools])
    def group_candidate():
        candidate=1-active;scalar[candidate]=scalar[active][:];cap_pool[candidate]=cap_pool[active][:];secure_pool[candidate]=secure_pool[active];fsuid_pool[candidate]=fsuid_pool[active]
        uid_pool[candidate]=uid_pool[active][:];user_links[candidate]=user_links[active][:];links[candidate]=links[active]
        return candidate
    def full_snapshot():
        s=snapshot()
        if cap_pool is not None:s['capabilities']=[v[:] for v in cap_pool]
        if secure_pool is not None:s['securebits']=secure_pool[:]
        if fsuid_pool is not None:s['fsuid']=fsuid_pool[:]
        if uid_pool is not None:s['uids']=[v[:] for v in uid_pool]
        if user_links is not None:s['user_links']=[v[:] for v in user_links]
        return s
    states=[full_snapshot()];expected=[]
    for ordinal,call in enumerate(recipes(profile)):
        n=call['number'];args=call['args'];before=input_words(profile,ordinal);words=before[:]
        current_uids=uid_pool[active] if uid_pool is not None else initial['uids']
        ids={172:initial['tgid'],178:initial['pid'],173:initial['ppid'],174:current_uids[0],175:current_uids[1],176:scalar[active][0],177:scalar[active][1]};raw=ids.get(n,0)
        if n==166:raw=mask;mask=args[0]&0o777
        if n in (148,150):
            for value,at in zip(current_uids if n==148 else scalar[active][:3],args):
                if at not in range(0,32,4):raw=(1<<64)-14;break
                words[at//4]=value
        if n==158:
            size=args[0]&0xffffffff;p=pools[links[active]];raw=p['ngroups']
            if size&0x80000000 or (size and size<p['ngroups']):raw=(1<<64)-22
            elif size:
                for j,value in enumerate(p['gid'][:p['ngroups']]):
                    at=args[1]+4*j
                    if at not in range(0,32,4):raw=(1<<64)-14;break
                    words[at//4]=value
        if n==159:
            size=args[0]&0xffffffff
            if denied or (cap_pool is not None and not cap_pool[active][0]&(1<<6)):raw=UNCHANGED
            elif size>65536:raw=(1<<64)-22
            else:
                if size>4:raise ValueError('setgroups recipe exceeds bounded allocation')
                index=next(i for i,p in enumerate(pools) if p['usage']==0);p=pools[index]
                p.update(usage=1,ngroups=size,gid=[0]*4)
                for j in range(size):
                    at=args[1]+4*j
                    if at not in range(0,32,4):raw=(1<<64)-14;break
                    value=before[at//4]
                    if value==0xffffffff:raw=(1<<64)-22;break
                    p['gid'][j]=value
                if raw:p['usage']=0
                else:
                    p['gid'][:size]=sorted(p['gid'][:size]);pools[links[active]]['usage']-=1
                    candidate=1-active
                    if cap_pool is not None:cap_pool[candidate]=cap_pool[active][:]
                    if secure_pool is not None:secure_pool[candidate]=secure_pool[active]
                    if fsuid_pool is not None:fsuid_pool[candidate]=fsuid_pool[active]
                    if uid_pool is not None:uid_pool[candidate]=uid_pool[active][:]
                    scalar[candidate]=scalar[active][:]
                    if user_links is not None:user_links[candidate]=user_links[active][:]
                    active=candidate;links[active]=index;generation+=1;epochs[active]=generation
        if n==90:
            header,data=args[:2]
            def read_cap(at):return before[at//4] if at in range(0,32,4) else None
            version=read_cap(header);count={0x19980330:1,0x20071026:2,0x20080522:2}.get(version)
            null_output=data==UNCHANGED
            if version is None:raw=(1<<64)-14
            elif count is None:
                words[header//4]=0x20080522;raw=0 if null_output else (1<<64)-22
            elif null_output:raw=0
            elif read_cap(header+4) is None:raw=(1<<64)-14
            elif read_cap(header+4)&0x80000000:raw=(1<<64)-22
            elif read_cap(header+4) not in (0,initial['pid']):raw=(1<<64)-3
            else:
                e,p,i=cap_pool[active][:3];payload=[e&0xffffffff,p&0xffffffff,i&0xffffffff,e>>32,p>>32,i>>32]
                for j,v in enumerate(payload[:3*count]):
                    at=data+4*j
                    if at not in range(0,32,4):raw=(1<<64)-14;break
                    words[at//4]=v
        if n==91:
            header,data=args[:2]
            def read(at):return before[at//4] if at in range(0,32,4) else None
            version=read(header);count={0x19980330:1,0x20071026:2,0x20080522:2}.get(version)
            if version is None:raw=(1<<64)-14
            elif count is None:words[header//4]=0x20080522;raw=(1<<64)-22
            elif read(header+4) is None:raw=(1<<64)-14
            elif read(header+4) not in (0,initial['pid']):raw=UNCHANGED
            elif any(read(data+4*j) is None for j in range(3*count)):raw=(1<<64)-14
            else:
                low=[read(data+4*j) for j in range(3)];high=[read(data+4*(j+3)) for j in range(3)] if count==2 else [0]*3
                e,p,i=[(a|(b<<32))&((1<<41)-1) for a,b in zip(low,high)]
                candidate=1-active;old=cap_pool[active];cap_pool[candidate]=old[:];links[candidate]=links[active]
                if secure_pool is not None:secure_pool[candidate]=secure_pool[active]
                if fsuid_pool is not None:fsuid_pool[candidate]=fsuid_pool[active]
                if uid_pool is not None:uid_pool[candidate]=uid_pool[active][:]
                scalar[candidate]=scalar[active][:]
                if user_links is not None:user_links[candidate]=user_links[active][:]
                old_e,old_p,old_i,bounding,ambient=old
                if (not old_e&(1<<8) and i&~(old_i|old_p)) or i&~(old_i|bounding) or p&~old_p or e&~p:raw=UNCHANGED
                else:
                    cap_pool[candidate]=[e,p,i,bounding,ambient&p&i];active=candidate;generation+=1;epochs[active]=generation
        if n==167:
            option,arg2,arg3,arg4,arg5=args;old=cap_pool[active];secure=secure_pool[active];new=old[:];new_secure=secure;publish=False
            valid=lambda bit:0<=bit<=40
            if option==23:raw=int(bool(old[3]&(1<<arg2))) if valid(arg2) else (1<<64)-22
            elif option==24:
                if not old[0]&(1<<8):raw=UNCHANGED
                elif not valid(arg2):raw=(1<<64)-22
                else:new[3]&=~(1<<arg2);publish=True
            elif option==27:raw=secure
            elif option==28:
                if ((secure&0xaa)>>1)&(secure^arg2) or secure&0xaa&~arg2 or arg2&~0xff or not old[0]&(1<<8):raw=UNCHANGED
                else:new_secure=arg2;publish=True
            elif option==7:raw=int(bool(secure&16))
            elif option==8:
                if arg2>1:raw=(1<<64)-22
                elif secure&32:raw=UNCHANGED
                else:new_secure=(secure|16) if arg2 else (secure&~16);publish=True
            elif option==47:
                if arg2==4:
                    if arg3|arg4|arg5:raw=(1<<64)-22
                    else:new[4]=0;publish=True
                elif not valid(arg3) or arg4 or arg5:raw=(1<<64)-22
                elif arg2==1:raw=int(bool(old[4]&(1<<arg3)))
                elif arg2 not in (2,3):raw=(1<<64)-22
                elif arg2==2 and (not old[1]&(1<<arg3) or not old[2]&(1<<arg3) or secure&64):raw=UNCHANGED
                else:
                    new[4]=(old[4]|(1<<arg3)) if arg2==2 else (old[4]&~(1<<arg3));publish=True
            else:raise ValueError('prctl option outside reviewed hook domain')
            if publish:
                candidate=1-active;cap_pool[candidate]=new;secure_pool[candidate]=new_secure;links[candidate]=links[active]
                if fsuid_pool is not None:fsuid_pool[candidate]=fsuid_pool[active]
                if uid_pool is not None:uid_pool[candidate]=uid_pool[active][:]
                scalar[candidate]=scalar[active][:]
                if user_links is not None:user_links[candidate]=user_links[active][:]
                active=candidate;generation+=1;epochs[active]=generation
        if n==151:
            value=args[0]&0xffffffff;old_fsuid=fsuid_pool[active];raw=old_fsuid
            if value!=0xffffffff:
                candidate=1-active;cap_pool[candidate]=cap_pool[active][:];secure_pool[candidate]=secure_pool[active];fsuid_pool[candidate]=old_fsuid;links[candidate]=links[active]
                if uid_pool is not None:uid_pool[candidate]=uid_pool[active][:]
                scalar[candidate]=scalar[active][:]
                if user_links is not None:user_links[candidate]=user_links[active][:]
                if (value in current_uids or value==old_fsuid or cap_pool[active][0]&(1<<7)) and value!=old_fsuid:
                    fsuid_pool[candidate]=value
                    if not secure_pool[active]&4:
                        if old_fsuid==0 and value!=0:cap_pool[candidate][0]&=~FS_CAPS
                        if old_fsuid!=0 and value==0:cap_pool[candidate][0]|=cap_pool[candidate][1]&FS_CAPS
                    active=candidate;generation+=1;epochs[active]=generation
        if n==147:
            values=[v&0xffffffff for v in args[:3]];old=uid_pool[active];old_caps=cap_pool[active];secure=secure_pool[active]
            noop=all(v==0xffffffff or (v==old[j] and (j!=1 or v==fsuid_pool[active])) for j,v in enumerate(values))
            if not noop:
                if any(v!=0xffffffff and v not in old for v in values) and not old_caps[0]&(1<<7):raw=UNCHANGED
                else:
                    candidate=1-active;uid_pool[candidate]=[old[j] if v==0xffffffff else v for j,v in enumerate(values)]
                    new=uid_pool[candidate];cap_pool[candidate]=old_caps[:];secure_pool[candidate]=secure;fsuid_pool[candidate]=new[1];links[candidate]=links[active]
                    scalar[candidate]=scalar[active][:]
                    if user_links is not None:user_links[candidate]=[[1001,0,9001,9002].index(new[0])]*2
                    if not secure&4:
                        if 0 in old and 0 not in new:
                            if not secure&16:cap_pool[candidate][0]=cap_pool[candidate][1]=0
                            cap_pool[candidate][4]=0
                        if old[1]==0 and new[1]!=0:cap_pool[candidate][0]=0
                        if old[1]!=0 and new[1]==0:cap_pool[candidate][0]=cap_pool[candidate][1]
                    active=candidate;generation+=1;epochs[active]=generation
        if n in (145,146):
            values=[v&0xffffffff for v in args[:2]];old=uid_pool[active];old_caps=cap_pool[active];secure=secure_pool[active]
            if n==146 and values[0]==0xffffffff:raw=(1<<64)-22
            else:
                candidate=1-active;uid_pool[candidate]=old[:];cap_pool[candidate]=old_caps[:];secure_pool[candidate]=secure;fsuid_pool[candidate]=fsuid_pool[active];links[candidate]=links[active];user_links[candidate]=user_links[active][:]
                scalar[candidate]=scalar[active][:]
                new=uid_pool[candidate];privileged=bool(old_caps[0]&(1<<7))
                if n==146:
                    value=values[0]
                    if privileged:new[0]=new[2]=value
                    elif value not in (old[0],old[2]):raw=UNCHANGED
                    if not raw:new[1]=value
                else:
                    r,e=values
                    if r!=0xffffffff:
                        new[0]=r
                        if r not in old[:2] and not privileged:raw=UNCHANGED
                    if not raw and e!=0xffffffff:
                        new[1]=e
                        if e not in old and not privileged:raw=UNCHANGED
                    if not raw and (r!=0xffffffff or (e!=0xffffffff and e!=old[0])):new[2]=new[1]
                if not raw:
                    user_links[candidate]=[[1001,0,9001,9002].index(new[0])]*2
                    fsuid_pool[candidate]=new[1]
                    if not secure&4:
                        if 0 in old and 0 not in new:
                            if not secure&16:cap_pool[candidate][0]=cap_pool[candidate][1]=0
                            cap_pool[candidate][4]=0
                        if old[1]==0 and new[1]!=0:cap_pool[candidate][0]=0
                        if old[1]!=0 and new[1]==0:cap_pool[candidate][0]=cap_pool[candidate][1]
                    active=candidate;generation+=1;epochs[active]=generation
        if n==149:
            values=[v&0xffffffff for v in args[:3]];old=scalar[active]
            same=all(v==0xffffffff or (v==old[j] and (j!=1 or v==old[3])) for j,v in enumerate(values))
            if not same:
                if any(v!=0xffffffff and v not in old[:3] for v in values) and not cap_pool[active][0]&GID:raw=UNCHANGED
                else:
                    candidate=group_candidate();scalar[candidate]=[old[j] if v==0xffffffff else v for j,v in enumerate(values)];scalar[candidate].append(scalar[candidate][1])
                    active=candidate;generation+=1;epochs[active]=generation
        if n==152:
            value=args[0]&0xffffffff;old=scalar[active];raw=old[3]
            if value!=0xffffffff:
                candidate=group_candidate()
                if (value in old or cap_pool[active][0]&GID) and value!=old[3]:
                    scalar[candidate][3]=value;active=candidate;generation+=1;epochs[active]=generation
        if n==144:
            value=args[0]&0xffffffff;old=scalar[active]
            if value==0xffffffff:raw=(1<<64)-22
            else:
                candidate=group_candidate()
                if cap_pool[active][0]&GID:scalar[candidate]=[value]*4
                elif value in (old[0],old[2]):scalar[candidate][1]=scalar[candidate][3]=value
                else:raw=UNCHANGED
                if not raw:active=candidate;generation+=1;epochs[active]=generation
        if n==143:
            r,e=[v&0xffffffff for v in args[:2]];old=scalar[active];candidate=group_candidate();new=scalar[candidate];privileged=bool(cap_pool[active][0]&GID)
            if r!=0xffffffff:
                if r in old[:2] or privileged:new[0]=r
                else:raw=UNCHANGED
            if not raw and e!=0xffffffff:
                if e in old[:3] or privileged:new[1]=e
                else:raw=UNCHANGED
            if not raw:
                if r!=0xffffffff or (e!=0xffffffff and e!=old[0]):new[2]=new[1]
                new[3]=new[1];active=candidate;generation+=1;epochs[active]=generation
        group=pools[links[active]]
        expected.append(dict(**call,raw_bits=raw,words=words,input_words=before,umask_after=mask,gids_after=scalar[active][:3],fsgid_after=scalar[active][3],groups_after=group['gid'][:group['ngroups']]))
        if denied:expected[-1]['cap_setgid_after']=initial['cap_setgid']
        if cap_pool is not None:expected[-1]['capabilities_after']=cap_pool[active][:]
        if secure_pool is not None:expected[-1]['securebits_after']=secure_pool[active]
        if fsuid_pool is not None:expected[-1]['fsuid_after']=fsuid_pool[active]
        if uid_pool is not None:expected[-1]['uids_after']=uid_pool[active][:]
        states.append(full_snapshot())
    return expected,states

def projection(capture):
    """Independent decoder of the reviewed unprivileged credential transitions."""
    initial=capture['initial'];profile=profile_for(capture)
    if profile in ('fd-dup','file-io','file-positioned','fd-control','close-range','fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):return fd_dup_projection(capture)
    if profile in ('setgroups','setgroups-denied','capabilities','capget','prctl','fsuid','setresuid','uid-setters','credential-setters'):return setgroups_projection(capture)
    mask=initial['umask'];active=0;generation=0
    pool=[[*initial['gids'],initial['gids'][1]] for _ in range(2)];epochs=[0,0]
    def snapshot():return dict(gids=list(pool[active][:3]),fsgid=pool[active][3],pool=[list(v) for v in pool],active=active,generation=generation,epochs=list(epochs))
    states=[snapshot()];expected=[]
    for call in recipes(profile):
        n=call['number'];args=call['args'];ids={172:initial['tgid'],178:initial['pid'],173:initial['ppid'],174:initial['uids'][0],175:initial['uids'][1],176:pool[active][0],177:pool[active][1]}
        raw=ids.get(n,0);words=[0xa5a50000+j for j in range(8)]
        if n==166:raw=mask;mask=args[0]&0o777
        if n==149:
            values=[v&0xffffffff for v in args];old=pool[active]
            same=all(v==0xffffffff or v==old[j] for j,v in enumerate(values)) and (values[1]==0xffffffff or values[1]==old[3])
            if not same:
                if any(v!=0xffffffff and v not in old[:3] for v in values):raw=UNCHANGED
                else:
                    new=[old[j] if v==0xffffffff else v for j,v in enumerate(values)];new.append(new[1])
                    active=1-active;generation+=1;pool[active]=new;epochs[active]=generation
        if n==152:
            value=args[0]&0xffffffff;old=pool[active];raw=old[3]
            if value!=0xffffffff:
                # Linux prepares credentials before permission/no-op checks.
                # Aborts leave a copied inactive slot, but do not publish it.
                candidate=1-active;pool[candidate]=list(old)
                if value in old and value!=old[3]:
                    pool[candidate][3]=value;active=candidate;generation+=1;epochs[active]=generation
        if n==144:
            value=args[0]&0xffffffff;old=pool[active]
            if value==0xffffffff:raw=(1<<64)-22
            else:
                candidate=1-active;pool[candidate]=list(old)
                if value not in (old[0],old[2]):raw=UNCHANGED
                else:
                    pool[candidate][1]=pool[candidate][3]=value
                    active=candidate;generation+=1;epochs[active]=generation
        if n==143:
            real,effective=[v&0xffffffff for v in args[:2]];old=pool[active]
            candidate=1-active;new=list(old);pool[candidate]=new
            if real!=0xffffffff and real not in old[:2]:raw=UNCHANGED
            else:
                if real!=0xffffffff:new[0]=real
                if effective!=0xffffffff and effective not in old[:3]:raw=UNCHANGED
                else:
                    if effective!=0xffffffff:new[1]=effective
                    if real!=0xffffffff or (effective!=0xffffffff and effective!=old[0]):new[2]=new[1]
                    new[3]=new[1];active=candidate;generation+=1;epochs[active]=generation
        if n in (148,150):
            for value,offset in zip(initial['uids'] if n==148 else pool[active][:3],args):
                if offset not in range(0,32,4):raw=(1<<64)-14;break
                words[offset//4]=value
        if n==158:
            size=args[0]&0xffffffff;groups=initial['groups'];offset=args[1];raw=len(groups)
            if size&0x80000000 or (size and size<len(groups)):raw=(1<<64)-22
            elif size:
                for j,value in enumerate(groups):
                    at=offset+4*j
                    if at not in range(0,32,4):raw=(1<<64)-14;break
                    words[at//4]=value
        row=dict(**call,raw_bits=raw,words=words,umask_after=mask)
        if profile in ('credentials','fsgid','group-setters','getgroups'):row.update(gids_after=pool[active][:3],fsgid_after=pool[active][3])
        if profile=='getgroups':row['groups_after']=list(initial['groups'])
        expected.append(row);states.append(snapshot())
    return expected,states

def fd_dup_plan():
    """Bounded descriptor lifetime, replacement, bitmap and error transitions."""
    out=[(str(i),c) for i,c in enumerate(recipes('minimal'))]
    def add(name,n,*args):out.append((name,dict(number=n,args=list(args)+[0]*(3-len(args)))))
    add('dup_closed',23,7)
    add('dup_invalid',23,UNCHANGED)
    add('same_fd',24,3,3,0)
    add('same_closed_fd',24,7,7,0)
    add('flags_before_bad_source',24,7,4,1)
    add('target_at_limit',24,3,8,0)
    add('invalid_target',24,3,UNCHANGED,0)
    add('bad_source',24,7,4,0)
    add('close_closed',57,7)
    add('close_invalid',57,UNCHANGED)
    add('dup_seed',23,3)
    add('dup_cloexec',24,3,6,0x80000)
    add('dup_hole',23,4)
    add('dup_last',23,6)
    add('table_full',23,3)
    add('bad_source_full',23,8)
    add('same_file_replace_clear',24,3,6,0)
    add('same_file_replace_cloexec',24,4,5,0x80000)
    add('close_cloexec',57,5)
    add('reuse_closed_clears_cloexec',23,6)
    add('close_low',57,4)
    add('console_replace_regular',24,1,5,0x80000)
    add('console_dup_lowest',23,1)
    add('regular_replace_console',24,3,4,0)
    add('regular_replace_console_cloexec',24,6,5,0x80000)
    add('close_original_seed',57,3)
    add('closed_source_alias_survives',23,3)
    add('alias_recreates_seed',23,6)
    add('close_stale_cloexec',57,5)
    add('closed_target_flag_error',24,3,5,2)
    add('truncated_source_and_target',24,0x100000003,0x100000005,0x100080000)
    add('truncated_close',57,0x100000005)
    add('truncated_dup',23,0x100000003)
    add('truncated_zero_flags',24,3,5,0x100000000)
    add('signed_flags_invalid',24,3,5,0xffffffff)
    add('close_high',57,7)
    add('dup3_new_preserves_next_fd',24,4,7,0x80000)
    add('full_after_fixed_install',23,3)
    add('close_for_console',57,4)
    add('console_dup_reused',23,0)
    add('close_console_alias',57,4)
    add('regular_dup_reused',23,6)
    add('close_alias_3',57,3)
    add('close_alias_4',57,4)
    add('close_alias_5',57,5)
    add('close_alias_6',57,6)
    add('last_regular_reference',57,7)
    add('all_regular_sources_closed',23,6)
    add('console_after_regular_release',23,2)
    add('console_fixed_cloexec',24,0,7,0x80000)
    add('close_console_3',57,3)
    add('close_console_7',57,7)
    add('final_closed_same_fd',24,3,3,0)
    return out

def file_io_plan():
    out=[(n,c,None) for n,c in fd_dup_plan()[:20]]
    def add(name,n,*args):out.append((name,dict(number=n,args=list(args)+[0]*(3-len(args))),None))
    add('read_initial',63,3,4,6)
    add('query_after_read',62,3,0,1)
    add('seek_start',62,3,0,0)
    add('overwrite_four',64,3,4,4)
    add('rewind_overwrite',62,3,0,0)
    add('read_overwrite',63,3,0,8)
    add('seek_end_back',62,3,UNCHANGED-3,2)
    add('extend_file',64,3,8,8)
    add('seek_sparse',62,3,28,0)
    add('write_sparse',64,3,4,4)
    add('read_gap_seek',62,3,20,0)
    add('read_zero_gap',63,3,0,12)
    add('read_eof_bad_pointer',63,3,UNCHANGED,4)
    add('zero_read_null',63,3,UNCHANGED,0)
    add('zero_write_bad_pointer',64,3,UNCHANGED-1,0)
    add('negative_seek',62,3,UNCHANGED,0)
    add('negative_relative_seek',62,3,UNCHANGED-40,1)
    add('invalid_whence',62,3,0,5)
    add('signed_whence',62,3,0,UNCHANGED)
    add('large_seek',62,3,0x100000007,0)
    add('large_offset_eof',63,3,4,8)
    add('rewind_for_faults',62,3,0,0)
    add('read_partial_fault',63,3,28,8)
    add('read_first_fault',63,3,UNCHANGED-1,4)
    add('read_guard_first_fault',63,3,32,4)
    add('write_partial_fault',64,3,28,8)
    add('write_first_fault',64,3,UNCHANGED,4)
    add('read_huge_count',63,3,0,1<<63)
    add('write_huge_count',64,3,0,1<<63)
    add('truncated_fd_read',63,0x100000003,4,4)
    add('truncated_whence',62,3,4,0x100000000)
    add('read_bad_fd_before_pointer',63,7,UNCHANGED,4)
    add('write_bad_fd_before_pointer',64,7,UNCHANGED-1,4)
    add('seek_bad_fd_before_whence',62,7,0,5)
    for n,c in fd_dup_plan()[20:]:
        out.append((n,c,None))
        if n=='dup_seed':
            add('alias_reads_shared_offset',63,4,0,4)
            add('alias_seek_updates_original',62,4,2,0)
            add('original_writes_alias_offset',64,3,4,6)
            add('alias_reads_after_original_write',63,4,8,4)
        if n=='close_original_seed':
            add('closed_original_read',63,3,4,4)
            add('surviving_alias_seek',62,6,0,0)
            add('surviving_alias_read',63,6,0,16)
            add('surviving_alias_write',64,6,4,4)
        if n=='last_regular_reference':
            add('last_alias_read_bad_fd',63,7,UNCHANGED,4)
            add('last_alias_write_bad_fd',64,7,UNCHANGED,4)
            add('last_alias_seek_bad_fd',62,7,0,0)
    return out

def file_positioned_plan():
    out=[]
    def add(name,n,*args):out.append((name,dict(number=n,args=list(args)+[0]*(4-len(args))),None))
    for name,call,data in file_io_plan():
        out.append((name,dict(number=call['number'],args=call['args']+[0]),data))
        if name=='seek_start':
            add('pread_initial_preserves_position',67,3,4,8,4)
            add('pwrite_overwrite_preserves_position',68,3,8,4,2)
            add('query_after_positioned',62,3,0,1)
            add('pread_negative_before_bad_fd',67,7,UNCHANGED,4,UNCHANGED)
            add('pwrite_negative_before_bad_fd',68,7,UNCHANGED-1,0,UNCHANGED)
            add('pread_closed_fd',67,7,UNCHANGED,4,0)
            add('pwrite_closed_fd',68,7,UNCHANGED,4,0)
            add('pread_console_espipe',67,0,UNCHANGED,0,0)
            add('pwrite_console_espipe',68,1,UNCHANGED,0,0)
            add('ftruncate_negative_before_bad_fd',46,7,UNCHANGED)
            add('ftruncate_closed_fd',46,7,4)
            add('ftruncate_console',46,0,4)
            add('pread_eof_null',67,3,UNCHANGED,4,16)
            add('pread_zero_null',67,3,UNCHANGED,0,0)
            add('pwrite_zero_null',68,3,UNCHANGED-1,0,63)
            add('pread_large_offset',67,3,4,4,0x100000007)
            add('pread_partial_fault',67,3,28,8,0)
            add('pwrite_partial_fault',68,3,28,8,8)
            add('pread_guard_first_fault',67,3,32,4,0)
            add('pwrite_first_fault',68,3,UNCHANGED,4,4)
            add('pread_huge_count',67,3,0,1<<63,0)
            add('pwrite_huge_count',68,3,0,1<<63,0)
            add('positioned_offsets_still_zero',62,3,0,1)
        if name=='write_sparse':
            add('shrink_below_position',46,3,6)
            add('read_after_shrink_eof',63,3,UNCHANGED,4)
            add('pread_across_shrunk_eof',67,3,0,12,2)
            add('expand_after_shrink',46,3,32)
            add('pread_expanded_zeros',67,3,0,24,6)
            add('pwrite_sparse_extension',68,3,4,4,40)
            add('truncate_empty_keeps_position',46,3,0)
            add('pread_empty_bad_pointer',67,3,UNCHANGED,4,0)
            add('extend_empty',46,3,48)
            add('pread_zero_filled_extension',67,3,0,32,8)
            add('pwrite_after_empty_extension',68,3,4,8,12)
            add('truncate_max_capacity',46,3,64)
            add('pread_at_capacity_tail',67,3,24,8,60)
            add('truncate_back_32',46,0x100000003,32)
            add('ftruncate_signed_high_length',46,3,0x8000000000000000)
        if name=='original_writes_alias_offset':
            add('pread_alias_keeps_shared_position',67,4,0,8,2)
            add('pwrite_alias_keeps_shared_position',68,4,4,4,24)
            add('shrink_via_alias',46,4,10)
            add('original_read_after_alias_shrink',63,3,8,4)
            add('extend_via_original',46,3,32)
            add('pread_alias_zero_tail',67,4,0,16,10)
        if name=='surviving_alias_write':
            add('pread_closed_original',67,3,UNCHANGED,4,0)
            add('pwrite_surviving_alias',68,6,4,4,4)
            add('truncate_surviving_alias',46,6,8)
            add('extend_surviving_alias',46,6,32)
            add('pread_surviving_alias',67,6,0,20,4)
        if name=='last_regular_reference':
            add('pread_after_last_close',67,7,UNCHANGED,4,0)
            add('pwrite_after_last_close',68,7,UNCHANGED,4,0)
            add('ftruncate_after_last_close',46,7,0)
            add('negative_position_after_last_close',67,7,UNCHANGED,0,UNCHANGED)
    return out

def fd_control_plan():
    """The fcntl workload plus writev and futex calls at a point where fd 3 is the regular file at position 0.

    The writev that succeeds writes back the file's own first eight bytes and is rewound, so every later call
    sees the file it saw before; the futex calls change no state (a private wake with no waiter, a wait on a
    changed value, an unaligned word, an unknown command)."""
    out=[]
    for row in fd_control_base_plan():
        out.append(row)
        if row[0]=='rewind_after_fcntl_alias':out+=vector_futex_calls()
    return out

# Input words: an iovec at offset 0 (one segment: base offset 16, length 8) and the segment's bytes at offset 16, the
# file's first eight bytes ('abcdefgh'); a negative segment length; and the futex word 7 at offset 0. iovec bases are
# app_words offsets the witness relocates to addresses for the call (application_source).
_IOV_ONE=(16,0,8,0,0x64636261,0x68676665,0xa5a50006,0xa5a50007)
_IOV_NEGATIVE=(16,0,8,0x80000000,0x64636261,0x68676665,0xa5a50006,0xa5a50007)
_FUTEX_WORD=(7,0xa5a50001,0xa5a50002,0xa5a50003,0xa5a50004,0xa5a50005,0xa5a50006,0xa5a50007)
def vector_futex_calls():
    """Fresh rows (and input lists) per plan: callers may change what they receive."""
    return [(n,dict(number=c['number'],args=list(c['args'])),None if d is None else list(d)) for n,c,d in FD_CONTROL_VECTOR_FUTEX_CALLS]
FD_CONTROL_VECTOR_FUTEX_CALLS=[
    ('writev_rewrites_seed_bytes',dict(number=66,args=[3,0,1,0]),_IOV_ONE),
    ('rewind_after_writev',dict(number=62,args=[3,0,0,0]),None),
    ('writev_no_segments',dict(number=66,args=[3,0,0,0]),_IOV_ONE),
    ('writev_bad_fd',dict(number=66,args=[8,0,1,0]),_IOV_ONE),
    ('writev_too_many_segments',dict(number=66,args=[3,0,1025,0]),_IOV_ONE),
    ('writev_negative_length',dict(number=66,args=[3,0,1,0]),_IOV_NEGATIVE),
    ('futex_wake_private_no_waiter',dict(number=98,args=[0,129,1,0,0,0]),_FUTEX_WORD),
    ('futex_wait_changed_value',dict(number=98,args=[0,128,6,0,0,0]),_FUTEX_WORD),
    ('futex_wake_unaligned',dict(number=98,args=[1,129,1,0,0,0]),_FUTEX_WORD),
    ('futex_unknown_command',dict(number=98,args=[0,142,0,0,0,0]),_FUTEX_WORD),
]

def fd_control_base_plan():
    """Five-command fcntl workload, preserving the prior 171-call order."""
    out=[]
    def add(name,n,*args):out.append((name,dict(number=n,args=list(args)+[0]*(4-len(args))),None))
    def ctl(name,fd,cmd,arg=0):add(name,25,fd,cmd,arg)
    for name,call,data in file_positioned_plan():
        if name=='read_initial':
            ctl('get_seed_cloexec',3,1)
            ctl('get_regular_status',3,3)
            ctl('get_console_status',1,3)
            ctl('clear_seed_cloexec',3,2)
            ctl('query_cleared_seed',3,1)
            ctl('set_ignored_flag_bits',3,2,2)
            ctl('query_ignored_flag_bits',3,1)
            ctl('set_seed_all_flag_bits',3,2,UNCHANGED)
            ctl('query_set_seed',3,1)
            ctl('duplicate_min_six',3,0,6)
            ctl('duplicate_cloexec_min_four',3,1030,4)
            ctl('query_plain_alias_flag',6,1)
            ctl('query_cloexec_alias_flag',4,1)
            ctl('set_alias_cloexec',6,2,1)
            ctl('query_original_independent_flag',3,1)
            ctl('clear_other_alias_flag',4,2)
            ctl('query_cleared_other_alias',4,1)
            ctl('query_shared_regular_status',6,3)
            add('fcntl_alias_reads_shared_file',63,6,4,4)
            add('fcntl_alias_offset_seen_original',62,3,0,1)
            add('rewind_after_fcntl_alias',62,3,0,0)
            ctl('duplicate_min_five',4,0,5)
            ctl('full_minimum_allocation',6,1030,7)
            ctl('duplicate_table_full',3,0)
            ctl('duplicate_minimum_at_limit',3,0,8)
            ctl('duplicate_negative_minimum',3,1030,UNCHANGED)
            ctl('bad_fd_before_minimum',8,0,8)
            ctl('bad_fd_before_unknown_command',8,0x7fffffff)
            ctl('unknown_command_valid_fd',3,0x7fffffff)
            add('close_for_minimum_reuse',57,5)
            ctl('reuse_minimum_with_cloexec',3,1030,5)
            add('close_stale_minimum_flag',57,5)
            ctl('reuse_minimum_clears_stale_flag',3,0,5)
            ctl('query_reused_minimum_flag',5,1)
            ctl('clear_high_alias_flag',6,2)
            ctl('clear_last_alias_flag',7,2)
            for fd in (4,5,6,7):add('release_fcntl_alias_'+str(fd),57,fd)
            ctl('truncated_descriptor_and_command',0x100000003,0x100000001)
            ctl('truncated_minimum',0x100000003,0x100000000,0x100000006)
            ctl('query_truncated_alias_flag',6,1)
            add('release_truncated_alias',57,6)
            ctl('closed_descriptor_flag',6,1)
            ctl('closed_descriptor_setflag',6,2,1)
            ctl('restore_seed_flag_after_controls',3,2,1)
        out.append((name,call,data))
        if name=='dup_seed':
            ctl('query_dup_alias_flag',4,1)
            ctl('set_dup_alias_flag',4,2,1)
            ctl('clear_original_with_alias_set',3,2)
            ctl('query_alias_after_original_clear',4,1)
            ctl('query_original_after_clear',3,1)
            ctl('restore_original_flag',3,2,1)
            ctl('restore_dup_alias_flag',4,2)
        if name=='close_original_seed':
            ctl('closed_original_fcntl',3,1)
            ctl('duplicate_surviving_cloexec',6,1030,3)
            ctl('query_recreated_cloexec',3,1)
            ctl('query_surviving_status',6,3)
            add('recreated_alias_sees_offset',62,3,0,1)
            add('release_recreated_alias',57,3)
        if name=='last_regular_reference':
            ctl('fcntl_after_last_reference',7,3)
            ctl('fcntl_bad_fd_before_negative_minimum',7,1030,UNCHANGED)
    return out

def close_range_plan():
    """Ranges alter the same table consumed by later inherited syscalls."""
    out=[]
    def add(name,n,*args):out.append((name,dict(number=n,args=list(args)+[0]*(4-len(args))),None))
    for name,call,data in fd_control_base_plan():
        if name=='close_alias_3':
            add('bulk_close_aliases',436,3,6,0)
            add('last_range_alias_reads_position',62,7,0,1)
            add('range_last_reference',436,7,0xffffffff,0)
            add('read_after_range_last_release',63,7,UNCHANGED,4)
            add('empty_range_close_again',436,3,0xffffffff,0)
        out.append((name,call,data))
        if name=='full_minimum_allocation':
            add('range_invalid_flags',436,4,7,1)
            add('range_reversed_bounds',436,7,4,0)
            add('range_invalid_before_unshare',436,4,7,10)
            add('range_signed_flags',436,4,7,UNCHANGED)
            add('range_truncated_closed_slots',436,0x100000008,0x10000000f,0x100000004)
            add('mark_full_tail',436,4,0xffffffff,4)
            add('query_range_marked_alias',25,4,1)
            add('query_range_marked_last_alias',25,7,1)
            add('close_middle_aliases',436,4,6,0)
            add('range_closed_alias_fcntl',25,4,1)
            add('range_survivor_read',63,7,4,4)
            add('range_survivor_offset_seen',62,3,0,1)
            add('range_rewind_original',62,3,0,0)
            add('close_middle_holes_again',436,4,6,0)
            add('close_high_empty_range',436,8,0xffffffff,0)
            add('mark_above_table_noop',436,64,0xffffffff,4)
            add('close_above_table_noop',436,0xffffffff,0xffffffff,0)
            add('range_truncated_reversed',436,0x100000007,0x100000004,0)
            add('range_reuse_first_hole',25,3,0,4)
            add('range_reuse_second_hole',25,3,0,5)
            add('range_reuse_last_hole_cloexec',25,3,1030,6)
            add('range_restore_allocation_hint',57,6)
            add('restore_range_aliases',24,3,6,0x80000)
            add('close_last_table_slot',436,63,0xffffffff,0)
            add('mark_console_slot',436,0,0,4)
            add('query_marked_console_slot',25,0,1)
            add('restore_console_slot_flag',25,0,2,0)
        if name=='last_regular_reference':
            add('mark_after_last_release',436,3,0xffffffff,4)
            add('range_still_no_regular_descriptor',25,7,1)
    return out

def stat_input_words():return [0x5a5a0000+j for j in range(32)]

def stat_metadata(initial):
    import struct
    raw=initial.get('stat_metadata')
    if not isinstance(raw,list) or len(raw)!=2:raise ValueError('native stat entry metadata missing')
    out=[]
    for i,values in enumerate(raw):
        if len(values)!=128 or any(type(v) is not int or not 0<=v<256 for v in values):raise ValueError('invalid stat entry bytes')
        b=bytes(values);dev,ino,mode,nlink,uid,gid,rdev=struct.unpack_from('<QQIIIIQ',b)
        decode=lambda v:(((v>>8)&0xfff)<<20)|(v&0xff)|((v>>12)&0xfff00)
        m=dict(dev=decode(dev),ino=ino,mode=mode,nlink=nlink,uid=uid,gid=gid,rdev=decode(rdev),blksize=struct.unpack_from('<I',b,56)[0],blocks=struct.unpack_from('<Q',b,64)[0])
        if mode&0o170000!=(0o20000 if i==0 else 0o100000) or m['blocks']!=(0 if i==0 else 8):raise ValueError('native stat class/allocation differs')
        if bytes(stat_bytes(m,0 if i==0 else 16,m['blocks']))!=b:raise ValueError('stat entry layout/padding/clock contract differs')
        out.append(m)
    return out

def stat_bytes(m,size,blocks):
    import struct
    encode=lambda v:((v&0xff)|((v>>20)<<8)|((v&0xfff00)<<12))
    b=bytearray(128)
    struct.pack_into('<QQIIIIQ',b,0,encode(m['dev']),m['ino'],m['mode'],m['nlink'],m['uid'],m['gid'],encode(m['rdev']))
    struct.pack_into('<qI',b,48,size,m['blksize']);struct.pack_into('<Q',b,64,blocks)
    return b

def fstat_plan():
    out=[]
    def query(name,fd,offset=0):out.append((name,dict(number=80,args=[fd,offset,0,0]),None))
    for name,call,data in close_range_plan():
        if name=='read_initial':
            query('stat_initial_regular',3);query('stat_console',1)
            query('stat_bad_fd_before_null',8,UNCHANGED);query('stat_null_output',3,UNCHANGED)
            query('stat_invalid_output',3,UNCHANGED-1);query('stat_partial_output',3,96)
            query('stat_guard_output',3,128);query('stat_truncated_fd',0x100000003)
        out.append((name,call,data))
        targets={'write_sparse':('stat_after_sparse_write',3),'shrink_below_position':('stat_after_shrink',3),
                 'truncate_empty_keeps_position':('stat_empty_unallocated',3),'extend_empty':('stat_extended_unallocated',3),
                 'pwrite_partial_fault':('stat_after_partial_write',3),'pwrite_alias_keeps_shared_position':('stat_alias_same_inode',4),
                 'shrink_via_alias':('stat_original_after_alias_shrink',3),'duplicate_surviving_cloexec':('stat_recreated_alias',3),
                 'bulk_close_aliases':('stat_last_surviving_alias',7),'range_last_reference':('stat_after_last_release',7)}
        if name in targets:query(*targets[name])
    query('stat_final_closed_fd',7)
    return out

def fchmod_plan():
    out=[]
    def change(name,fd,mode):out.append((name,dict(number=52,args=[fd,mode,0,0]),None))
    def query(name,fd=3):out.append((name,dict(number=80,args=[fd,0,0,0]),None))
    for name,call,data in fstat_plan():
        out.append((name,call,data))
        if name=='stat_initial_regular':
            change('chmod_bad_fd',8,0o600);change('chmod_console_denied',1,0o600)
            change('chmod_owner_600',3,0o600);query('stat_mode_600')
            change('chmod_narrow_mode',0x100000003,0x1000041a0);query('stat_mode_640')
            change('chmod_owner_none',3,0);query('stat_mode_none')
        if name=='write_sparse':
            change('chmod_owner_readonly',3,0o400);query('stat_mode_readonly')
        if name=='pwrite_alias_keeps_shared_position':
            change('chmod_via_alias',4,0o604);query('stat_mode_shared_alias')
        if name=='shrink_via_alias':
            change('chmod_restore_640',3,0o640);query('stat_mode_restored_alias',4)
        if name=='range_last_reference':
            change('chmod_after_last_release',7,0o600);query('stat_mode_after_release',7)
    change('chmod_final_closed_fd',7,0o777)
    return out

def fchown_plan():
    out=[]
    def change(name,fd,uid=UNCHANGED,gid=UNCHANGED):out.append((name,dict(number=55,args=[fd,uid,gid,0]),None))
    def query(name,fd=3):out.append((name,dict(number=80,args=[fd,0,0,0]),None))
    for name,call,data in fchmod_plan():
        out.append((name,call,data))
        if name=='stat_mode_600':
            change('chown_bad_fd',8);change('chown_console_denied',1,0)
            change('chown_same_owner',3,1002)
            change('chown_effective_group',3,gid=2002);query('stat_group_2002')
            change('chown_foreign_uid_denied',3,9001)
            change('chown_foreign_group_denied',3,gid=3001);query('stat_group_after_denials')
            change('chown_sentinels_keep_group',3);query('stat_group_sentinels')
            change('chown_narrow_arguments',0x100000003,0x1000003ea,0x100000000);query('stat_group_narrowed')
        if name=='stat_mode_none':
            change('chown_no_access_mode',3,gid=2002);query('stat_group_no_access')
        if name=='stat_mode_shared_alias':
            change('chown_via_alias',4,gid=0);query('stat_group_alias_zero')
            change('chown_original_shared',3,gid=2002);query('stat_group_alias_2002',4)
        if name=='stat_mode_restored_alias':
            change('chown_denied_pair_atomic',4,9001,0);query('stat_group_denied_atomic',4)
            change('chown_restore_group',3,gid=0);query('stat_group_restored',4)
        if name=='range_last_reference':
            change('chown_after_last_release',7,1002,0);query('stat_owner_after_release',7)
    change('chown_final_closed_fd',7)
    return out

def fchown_capable_plan():
    out=[]
    def call(name,n,*a):out.append((name,dict(number=n,args=list(a)+[0]*(4-len(a))),None))
    def change(name,fd,uid=UNCHANGED,gid=UNCHANGED):call(name,55,fd,uid,gid)
    def query(name,fd=3):call(name,80,fd,0)
    for name,entry,data in fchmod_plan():
        out.append((name,entry,data))
        if name=='stat_mode_600':
            change('privileged_bad_fd',8,9001,3001)
            change('privileged_console_same_owner',1,0)
            change('privileged_transfer',3,9001,3001);query('stat_privileged_transfer')
            call('privileged_chmod_nonowner_denied',52,3,0o777);query('stat_privileged_denied_mode')
            change('privileged_foreign_owner_group',3,gid=3003)
            change('privileged_sentinels',3);query('stat_privileged_sentinels')
            change('privileged_narrow_restore',0x100000003,0x1000003ea,0x100000000);query('stat_privileged_restored')
        if name=='stat_mode_none':
            change('privileged_no_access',3,0,4001);query('stat_privileged_no_access')
            call('privileged_pread_foreign_owner',67,3,0,1,0)
            call('privileged_chmod_zero_owner_denied',52,3,0o600)
            change('privileged_reclaim_from_root',3,1002,0);query('stat_privileged_reclaimed')
        if name=='stat_mode_shared_alias':
            change('privileged_alias_transfer',4,9002,4003);query('stat_privileged_alias_transfer')
            call('privileged_chmod_original_denied',52,3,0o600)
            change('privileged_original_group',3,gid=4007);query('stat_privileged_alias_group',4)
            change('privileged_alias_reclaim',4,1002,0);query('stat_privileged_restored_alias',4)
        if name=='range_last_reference':
            change('privileged_after_last_release',7,9001,3001);query('stat_privileged_after_release',7)
    change('privileged_final_closed_fd',7)
    return out

FILE_CAP_BOOT=1<<22
FILE_CAP_INITIAL=FILE_CAP_BOOT|9

def file_capabilities_plan():
    out=[]
    def call(name,n,*a,data=None):out.append((name,dict(number=n,args=list(a)+[0]*(4-len(a))),data))
    def caps(name,e,p=FILE_CAP_INITIAL,i=0,header=0,data=8,version=0x20080522,pid=0):
        call(name,91,header,data,data=[version,pid,e&0xffffffff,p&0xffffffff,i&0xffffffff,e>>32,p>>32,i>>32])
    def owner(name,fd=3,uid=UNCHANGED,gid=UNCHANGED):call(name,55,fd,uid,gid)
    def mode(name,fd=3,value=0o600):call(name,52,fd,value)
    def stat(name,fd=3):call(name,80,fd,0)
    for name,entry,data in fchown_capable_plan():
        out.append((name,entry,data))
        if name=='stat_privileged_restored':
            caps('file_caps_drop_chown',0)
            owner('file_caps_transfer_denied',uid=9001,gid=3001);stat('file_caps_stat_denied')
            caps('file_caps_bad_version',1,version=0)
            caps('file_caps_bad_pid',1,pid=23)
            caps('file_caps_guard_copy',1,data=24)
            caps('file_caps_null_header',1,header=UNCHANGED)
            caps('file_caps_subset_denied',64)
            caps('file_caps_inheritable_denied',0,i=64)
            caps('file_caps_regain_chown',1)
            owner('file_caps_transfer_again',uid=9001,gid=3001);stat('file_caps_stat_transferred')
            caps('file_caps_fowner_only',8)
            mode('file_caps_chmod_foreign',value=0o400);stat('file_caps_stat_foreign_mode')
            owner('file_caps_reclaim_denied',uid=1002,gid=0)
            caps('file_caps_drop_fowner',0)
            mode('file_caps_chmod_denied',value=0o777);stat('file_caps_stat_dropped_mode')
            caps('file_caps_both',9)
            owner('file_caps_reclaim',uid=1002,gid=0)
            mode('file_caps_restore_mode',value=0o600)
            caps('file_caps_restore_chown',1);stat('file_caps_stat_restored')
        if name=='stat_privileged_restored_alias':
            caps('file_caps_alias_both',9)
            owner('file_caps_alias_transfer',4,9002,4003)
            mode('file_caps_alias_chmod',3,0o400);stat('file_caps_stat_alias',4)
            caps('file_caps_alias_drop_fowner',1)
            mode('file_caps_alias_denied',4,0o777)
            owner('file_caps_alias_reclaim',3,1002,0)
            mode('file_caps_alias_restore_mode',4,0o604)
        if name=='stat_mode_restored_alias':
            caps('file_caps_remove_chown_permitted',8,FILE_CAP_BOOT|8)
            owner('file_caps_permanent_transfer_denied',4,9002,4003)
            caps('file_caps_regain_removed_denied',9,FILE_CAP_BOOT|9)
            stat('file_caps_stat_permitted_removed',4)
            caps('file_caps_remove_fowner_permitted',0,FILE_CAP_BOOT)
            caps('file_caps_regain_fowner_denied',8,FILE_CAP_BOOT|8)
            stat('file_caps_stat_all_removed',4)
    return out

def file_fsgid_plan():
    out=[]
    def call(name,n,*a,data=None):out.append((name,dict(number=n,args=list(a)+[0]*(4-len(a))),data))
    def fs(name,gid):call(name,152,gid)
    def group(name,gid,fd=3):call(name,55,fd,UNCHANGED,gid)
    def stat(name,fd=3):call(name,80,fd,0)
    def caps(name,e):call(name,91,0,8,data=[0x20080522,0,e,FILE_CAP_INITIAL,0,0,0,0])
    for name,entry,data in file_capabilities_plan():
        out.append((name,entry,data))
        if name=='file_caps_stat_denied':
            fs('file_fsgid_real',2001);call('file_fsgid_effective_query',177)
            group('file_fsgid_real_group',2001);stat('file_fsgid_stat_real')
            group('file_fsgid_effective_group_denied',2002);stat('file_fsgid_stat_denied')
            fs('file_fsgid_foreign_denied',3001)
            fs('file_fsgid_invalid_query',UNCHANGED)
            fs('file_fsgid_same_no_publish',2001)
            fs('file_fsgid_saved_narrow',0x1000007d3)
            group('file_fsgid_saved_group',2003);stat('file_fsgid_stat_saved')
            group('file_fsgid_real_group_denied',2001)
            group('file_fsgid_supplementary_group',0);stat('file_fsgid_stat_supplementary')
            fs('file_fsgid_restore_effective',2002)
            group('file_fsgid_effective_group_restored',2002);stat('file_fsgid_stat_effective')
            group('file_fsgid_restore_group_zero',0);stat('file_fsgid_stat_restored')
        if name=='file_caps_alias_reclaim':
            caps('file_fsgid_alias_drop_chown',0)
            fs('file_fsgid_alias_saved',2003)
            group('file_fsgid_alias_saved_group',2003,4);stat('file_fsgid_stat_alias_saved',3)
            fs('file_fsgid_alias_real',2001)
            group('file_fsgid_alias_real_group',2001,3);stat('file_fsgid_stat_alias_real',4)
            fs('file_fsgid_alias_query',UNCHANGED)
            caps('file_fsgid_alias_refresh_dropped',0)
            fs('file_fsgid_alias_restore',2002)
            group('file_fsgid_alias_group_restore',0,4)
            caps('file_fsgid_alias_restore_chown',1)
    return out

def file_fsuid_plan():
    out=[]
    def call(name,n,*a,data=None):out.append((name,dict(number=n,args=list(a)+[0]*(4-len(a))),data))
    def fs(name,uid):call('file_fsuid_'+name,151,uid)
    def group(name,gid):call('file_fsuid_'+name,152,gid)
    def owner(name,uid,gid=UNCHANGED,fd=3):call('file_fsuid_'+name,55,fd,uid,gid)
    def mode(name,bits,fd=3):call('file_fsuid_'+name,52,fd,bits)
    def stat(name,fd=3):call('file_fsuid_stat_'+name,80,fd,0)
    def caps(name):call('file_fsuid_'+name,91,0,8,data=[0x20080522,0,0,FILE_CAP_INITIAL,0,0,0,0])
    for name,entry,data in file_fsgid_plan():
        out.append((name,entry,data))
        if name=='file_fsgid_stat_restored':
            fs('real',1001);call('file_fsuid_effective_query',175)
            mode('real_mode_denied',0o640);owner('real_owner_denied',1002)
            stat('real_denied')
            fs('foreign_denied',9001);fs('invalid_query',UNCHANGED);fs('same_no_publish',1001)
            fs('root_narrow',0x100000000)
            owner('root_transfer',9001,3001);mode('root_mode',0o640);stat('root_foreign')
            fs('drop_root',1001);mode('dropped_mode_denied',0o604);owner('dropped_reclaim_denied',1001);stat('dropped')
            fs('root_reclaim',0);owner('reclaim_real',1001,2001)
            fs('become_owner',1001);mode('owner_mode',0o604);owner('owner_group',UNCHANGED,2002);stat('owner')
            caps('refresh_nondefault');group('saved_group',2003);owner('owner_saved_group',UNCHANGED,2003);stat('owner_group')
            fs('effective',1002);mode('effective_nonowner_denied',0o600);stat('effective_denied')
            fs('root_restore',0);owner('restore_owner',1002,0);mode('restore_mode',0o600)
            fs('restore_effective',1002);group('restore_group',2002);stat('restored')
        if name=='file_fsgid_alias_refresh_dropped':
            fs('alias_real',1001);mode('alias_nonowner_denied',0o604,4)
            fs('alias_root',0);owner('alias_transfer',1001,2001,4)
            fs('alias_become_owner',1001);mode('alias_mode',0o604,3)
            caps('alias_refresh_nondefault');group('alias_saved_group',2003)
            owner('alias_group',UNCHANGED,2003,4);stat('alias_group',3)
            fs('alias_root_restore',0);owner('alias_restore_owner',1002,2001,3);mode('alias_restore_mode',0o400,4)
            fs('alias_restore_effective',1002);group('alias_restore_group',2001);stat('alias_restored',4)
    return out

def file_groups_plan():
    out=[];permitted=FILE_CAP_INITIAL|64
    def call(name,n,*a,data=None):out.append(('file_groups_'+name,dict(number=n,args=list(a)+[0]*(4-len(a))),data))
    def words(values,at=0):
        result=[0xa5a50000+j for j in range(8)];result[at:at+len(values)]=values;return result
    def caps(name,e,p=permitted):call(name,91,0,8,data=[0x20080522,0,e,p,0,0,0,0])
    def put(name,values):call(name,159,len(values),0,data=words(values))
    def owner(name,gid,fd=3):call(name,55,fd,UNCHANGED,gid)
    def stat(name,fd=3):call('stat_'+name,80,fd,0)
    for ordinal,(name,entry,data) in enumerate(file_fsuid_plan()):
        out.append((name,entry,data))
        if ordinal==19:
            call('denied_negative_size',159,UNCHANGED,UNCHANGED)
            call('denied_guard',159,2,28,data=words([4009],7))
            caps('gain_setgid',64)
            put('duplicates',[4007,4001,4003,4003])
            call('query_count',158,0,UNCHANGED);call('query_small',158,3,0)
            call('query_full',158,4,0);call('query_partial',158,4,28)
            owner('member_group',4003);stat('duplicates')
            owner('foreign_group_denied',4009)
            caps('drop_effective',0)
            put('denied_replacement',[4009]);call('denied_invalid_size',159,65537,UNCHANGED)
            caps('refresh_nondefault',0)
            call('fsgid_real',152,2001);owner('second_member_group',4007)
            owner('egid_not_member_denied',2002)
            call('fsuid_real',151,1001);owner('nonowner_member_denied',4003)
            call('fsuid_restore',151,1002);stat('no_effective')
            caps('regain_setgid',64)
            call('empty',159,0,UNCHANGED);call('query_empty',158,0,UNCHANGED)
            call('query_empty_null',158,1,UNCHANGED);call('query_negative',158,UNCHANGED,0)
            owner('removed_member_denied',4001);owner('fsgid_group',2001)
            owner('removed_zero_denied',0);stat('empty')
            call('oversize',159,65537,UNCHANGED)
            call('invalid_gid',159,2,0,data=words([4009,0xffffffff]))
            call('partial_copy',159,2,28,data=words([4005],7))
            call('query_after_fault',158,0,UNCHANGED)
            call('replace_narrow_count',159,0x100000002,0,data=words([5003,5001]))
            call('alias',24,3,4,0)
            owner('alias_member',5001,4);stat('alias_first',3)
            caps('alias_drop_effective',0);put('alias_denied_replacement',[6001])
            owner('alias_second_member',5003,4);stat('alias',3)
            caps('alias_refresh_nondefault',0)
            call('root_fsuid',151,0)
            put('root_no_setgid_denied',[6001]);call('drop_root_fsuid',151,1002)
            owner('alias_member_restored',5001,3)
            caps('restore_setgid',64);put('restore_groups',[0])
            call('restore_fsgid',152,2002);owner('restore_inode_group',0,4)
            call('close_alias',57,4)
            caps('remove_permitted_setgid',1,FILE_CAP_INITIAL)
            caps('regain_removed_setgid_denied',64)
            put('permanent_denied',[6001]);stat('restored')
    return out

def file_group_setters_plan():
    out=[];permitted=FILE_CAP_INITIAL|64
    def call(name,n,*a,data=None):out.append(('file_group_setters_'+name,dict(number=n,args=list(a)+[0]*(4-len(a))),data))
    def caps(name,e):call(name,91,0,8,data=[0x20080522,0,e,permitted,0,0,0,0])
    def owner(name,gid,fd=4):call(name,55,fd,UNCHANGED,gid)
    def stat(name,fd=3):call('stat_'+name,80,fd,0)
    def query(name):call('query_'+name,150,0,4,8)
    def groups(name,values):
        words=[0xa5a50000+j for j in range(8)];words[:len(values)]=values;call(name,159,len(values),0,data=words)
    for name,entry,data in file_groups_plan():
        out.append((name,entry,data))
        if name=='file_groups_restore_inode_group':
            call('res_foreign',149,7001,7002,7003)
            call('getgid_foreign',176);call('getegid_foreign',177);query('foreign')
            owner('effective_group',7002);stat('privileged')
            call('gid_narrow',144,(1<<32)|8001);query('all_gid')
            owner('all_gid_group',8001);owner('old_effective_denied',7002)
            call('regid_foreign',143,8101,8102);query('regid_saved')
            owner('regid_group',8102)
            caps('drop_setgid',0)
            call('gid_real',144,8101);query('real')
            owner('real_group',8101);stat('real')
            call('gid_foreign_denied',144,9001);call('gid_invalid',144,UNCHANGED)
            call('gid_saved',144,8102)
            call('regid_partial_denied',143,8102,9003);query('partial_abort')
            call('res_foreign_denied',149,9003,UNCHANGED,UNCHANGED)
            call('fsgid_real',152,8101);owner('fsgid_group',8101)
            owner('egid_not_fsgid_denied',8102)
            call('res_all_sentinel',149,UNCHANGED,UNCHANGED,UNCHANGED)
            stat('distinct_fsgid')
            call('res_repair_fsgid',149,UNCHANGED,8102,UNCHANGED)
            owner('repaired_group',8102);stat('repair')
            call('regid_real_effective',143,UNCHANGED,8101);query('saved_preserved')
            owner('new_effective_group',8101)
            call('regid_collapse_saved',143,8101,UNCHANGED);query('saved_collapsed')
            call('gid_lost_saved_denied',144,8102)
            call('res_same_no_publish',149,8101,8101,8101)
            call('query_guard',150,0,28,32)
            caps('regain_setgid',64)
            call('res_nondefault',149,8201,8202,8203)
            caps('copy_nondefault',0);call('copy_fsgid',152,8201)
            owner('nondefault_group',8201);stat('nondefault_copy')
            call('copy_fsuid_real',151,1001);call('copy_fsuid_restore',151,1002)
            owner('nondefault_egid_denied',8202)
            caps('groups_setgid',64);groups('copy_groups',[0,8301])
            owner('supplementary_group',8301);stat('supplementary')
            groups('restore_groups',[0])
            call('gid_restore_all',144,2002)
            call('res_restore_ids',149,2001,2002,2003)
            owner('restore_inode_group',0);query('restored');stat('restored')
    return out

def file_status_plan():
    out=[];append=0x400;nonblock=0x800;noatime=0x40000
    def call(name,n,*a,data=None):out.append(('file_status_'+name,dict(number=n,args=list(a)+[0]*(4-len(a))),data))
    def flags(name,value,fd=4):call(name,25,fd,4,value)
    def get(name,fd=3):call(name,25,fd,3)
    def stat(name,fd=3):call('stat_'+name,80,fd,0)
    def payload(value,at=0):
        result=[0xa5a50000+j for j in range(8)]
        for j in range(0,len(value),4):result[at+j//4]=int.from_bytes(value[j:j+4],'little')
        return result
    def caps(name,e):call(name,91,0,8,data=[0x20080522,0,e,FILE_CAP_INITIAL|64,0,0,0,0])
    for name,entry,data in file_group_setters_plan():
        out.append((name,entry,data))
        if name=='file_group_setters_stat_restored':
            flags('append_nonblock_ignored',append|nonblock|0x40|0x200|0x80000)
            get('get_shared');call('get_alias_cloexec',25,4,1)
            call('seek_before_append',62,3,0,0)
            call('write_append',64,4,0,4,data=payload(b'APND'));stat('append')
            call('seek_before_pwrite',62,3,2,0)
            call('pwrite_append',68,4,0,4,0,data=payload(b'PWRT'));stat('pwrite')
            call('pwrite_high_append',68,3,0,4,1<<33,data=payload(b'HIGH'))
            call('append_partial',64,3,28,8,data=payload(b'PART',7))
            call('seek_before_fault',62,4,5,0)
            call('append_fault',64,4,UNCHANGED-1,4)
            call('append_zero',64,3,0,0)
            call('pwrite_zero',68,4,0,0,0)
            call('negative_pwrite',68,3,0,4,UNCHANGED,data=payload(b'NEGA'))
            call('duplicate_status',25,4,0,5);get('get_new_alias',5)
            call('mark_new_cloexec',25,5,2,1);get('get_original_flags')
            call('mark_alias_cloexec',25,4,2,1);stat('alias',5)
            flags('clear_append',nonblock|1|0x200,3);get('get_cleared',4)
            call('seek_before_overwrite',62,4,1,0)
            call('write_overwrite',64,5,0,4,data=payload(b'OVER'))
            call('pwrite_normal',68,3,0,4,0,data=payload(b'NORM'));stat('overwrite')
            flags('append_narrow',(1<<32)|append,5);get('get_narrow',4)
            call('close_original',57,3);call('seek_survivor',62,5,0,0)
            call('write_survivor',64,4,0,4,data=payload(b'TAIL'))
            call('reinstall_original',23,4);call('restore_original_cloexec',25,3,2,1)
            get('get_reopened');stat('reopened')
            call('close_new_alias',57,5)
            flags('owner_noatime',noatime|append)
            call('fsuid_nonowner',151,1001)
            flags('retain_noatime',noatime|nonblock,3);get('get_retained',4)
            flags('clear_noatime',nonblock,3)
            flags('noatime_denied',noatime|nonblock);stat('noatime_denied')
            call('fsuid_owner',151,1002)
            caps('gain_fowner',64|8);call('fsuid_capable_nonowner',151,1001)
            flags('capable_noatime',noatime)
            caps('drop_fowner',64)
            flags('retain_after_drop',noatime|append,3);get('get_after_drop')
            flags('clear_after_drop',append)
            flags('denied_after_drop',append|noatime,3)
            flags('restore_flags',0x80000)
            call('restore_alias_cloexec',25,4,2,0)
            call('restore_fsuid',151,1002)
            call('restore_empty',46,3,0)
            call('restore_data',68,4,0,16,0,data=payload(b'abcdefghijklmnop'))
            call('restore_position',62,3,0,0);stat('restored')
            call('bad_fd_flags',25,8,4,append|noatime)
    return out

def file_capget_plan():
    """Read live capabilities among file/credential transitions without publishing."""
    out=[]
    def query(name,version=0x20080522,pid=0,header=0,data=8):
        words=[0xa5a50000+j for j in range(8)]
        if header in range(0,32,4):words[header//4]=version
        if header+4 in range(0,32,4):words[(header+4)//4]=pid
        out.append(('file_capget_'+name,dict(number=90,args=[header,data,0,0]),words))
    markers={'file_fsuid_root_narrow':'root_gain','file_fsuid_drop_root':'root_drop',
             'file_status_gain_fowner':'fowner_gain','file_status_drop_fowner':'fowner_drop',
             'file_group_setters_setres_privileged':'gid_changed'}
    for i,(name,entry,data) in enumerate(file_status_plan()):
        out.append((name,entry,data))
        if i==19:
            query('initial');query('initial_legacy',0x19980330);query('initial_v2',0x20071026,pid=1)
        if name in markers:
            query(markers[name]);query(markers[name]+'_v2',0x20071026,pid=1)
        elif entry['number']==91:query('after_'+name)
        if name=='file_status_drop_fowner':
            query('unknown_null',version=0,data=UNCHANGED)
            query('unknown_output',version=0)
            query('null_negative_pid',pid=0xffffffff,data=UNCHANGED)
            query('tail_null',header=28,data=UNCHANGED)
            query('tail_pid_fault',header=28)
            query('negative_pid',pid=0xffffffff)
            query('missing_pid',pid=0x7fffffff)
            query('guard_output',data=32)
            query('partial_output',data=24)
            query('partial_output_v2',version=0x20071026,data=24)
            query('partial_legacy',version=0x19980330,data=24)
            query('null_header',header=UNCHANGED)
            query('bad_header',header=UNCHANGED-1)
            query('bad_output',data=UNCHANGED-1)
            query('aliased_output',data=0)
            query('aliased_v2',version=0x20071026,data=0)
            query('legacy',version=0x19980330)
    query('final');query('final_v2',version=0x20071026,pid=1)
    return out

def file_prctl_plan():
    """Privileged commoncap setup followed by the unchanged inherited session."""
    out=[];permitted=FILE_CAP_INITIAL|64|256
    def call(name,n,*args,data=None):out.append(('file_prctl_'+name,dict(number=n,args=list(args)+[0]*(5-len(args))),data))
    def pr(name,*args):call(name,167,*args)
    def caps(name,e,p=permitted,i=9):call(name,91,0,8,data=[0x20080522,0,e,p,i,0,0,0])
    def get(name):call(name,90,0,8,data=[0x20080522,0]+[0xa5a50000+j for j in range(2,8)])
    for index,(name,entry,data) in enumerate(file_capget_plan()):
        out.append((name,dict(number=entry['number'],args=entry['args']+[0]),data))
        if index!=19:continue
        pr('initial_securebits',27);pr('initial_bounding_high',23,40)
        pr('drop_invalid_unprivileged',24,41)
        caps('gain_setpcap',329)
        pr('drop_high',24,40);pr('read_dropped_high',23,40);pr('drop_high_again',24,40)
        pr('invalid_cap_privileged',24,41);pr('high_unsigned_cap',23,(1<<32)|40)
        pr('narrow_option',(1<<32)|23,40)
        pr('ambient_missing_inheritable',47,2,6)
        pr('ambient_raise',47,2,0);pr('ambient_is_set',47,1,0)
        pr('ambient_bad_arg4',47,1,0,1);pr('ambient_bad_arg5',47,1,0,0,1)
        pr('ambient_unknown',47,9,0);pr('ambient_invalid_cap',47,1,41)
        caps('remove_effective_file_bits',320)
        call('nonowner',151,1001)
        call('ambient_chown_denied',55,3,9001,UNCHANGED)
        call('ambient_noatime_denied',25,3,4,0x40000)
        get('ambient_does_not_grant_effective')
        pr('suppress_fixup',28,4);call('suppressed_root',151,0)
        get('suppressed_caps');call('suppressed_chown_denied',55,3,9001,UNCHANGED)
        pr('enable_fixup',28,0);call('leave_suppressed_root',151,1001)
        call('root_fixup',151,0);get('root_caps')
        call('root_transfer',55,3,9001,0);call('root_reclaim',55,3,1002,0)
        call('restore_fsuid',151,1002)
        caps('drop_inheritable_chown',329,i=8);pr('ambient_cleared_by_capset',47,1,0)
        pr('ambient_fowner',47,2,3)
        pr('clear_bad_arg3',47,4,1);pr('clear_bad_arg4',47,4,0,1);pr('clear_bad_arg5',47,4,0,0,1)
        pr('clear_ambient',47,4);pr('lower_clear_again',47,3,3)
        pr('forbid_ambient',28,64);pr('raise_forbidden',47,2,3);pr('allow_ambient',28,0)
        caps('drop_effective_setpcap',64,i=8)
        pr('drop_invalid_without_privilege',24,41);pr('securebits_denied',28,64)
        pr('keepcaps_invalid',8,2);pr('keepcaps_on',8,1);pr('get_keepcaps',7);pr('keepcaps_off',8,0)
        caps('regain_setpcap',329,i=8)
        pr('lock_keepcaps',28,48);pr('get_locked_securebits',27)
        pr('clear_locked_keepcaps',8,0);pr('unlock_rejected',28,16);pr('change_locked_rejected',28,0)
        pr('unsupported_securebits',28,496);pr('same_locked_securebits',28,48)
        caps('remove_permitted_setpcap',1,p=FILE_CAP_INITIAL|64,i=0)
        get('restored_caps');pr('drop_after_permitted_removal',24,40)
        pr('get_persistent_bounding',23,40);pr('get_persistent_securebits',27)
    pr('final_bounding',23,40);pr('final_ambient',47,1,0)
    pr('final_keepcaps',7);pr('final_securebits',27)
    pr('final_drop_denied',24,40);pr('final_keepcaps_denied',8,0)
    get('final_caps')
    return out

def file_prctl_update(args,old,secure):
    """Independent bounded commoncap projection, before credential publication."""
    option=args[0]&0xffffffff;arg2,arg3,arg4,arg5=args[1:]
    new=old[:];new_secure=secure;publish=False;raw=0
    valid=lambda bit:0<=bit<=40
    if option==23:raw=int(bool(old[3]&(1<<arg2))) if valid(arg2) else -22
    elif option==24:
        if not old[0]&256:raw=-1
        elif not valid(arg2):raw=-22
        else:new[3]&=~(1<<arg2);publish=True
    elif option==27:raw=secure
    elif option==28:
        if ((secure&0xaa)>>1)&(secure^arg2) or secure&0xaa&~arg2 or arg2&~0xff or not old[0]&256:raw=-1
        else:new_secure=arg2;publish=True
    elif option==7:raw=int(bool(secure&16))
    elif option==8:
        if arg2>1:raw=-22
        elif secure&32:raw=-1
        else:new_secure=(secure|16) if arg2 else (secure&~16);publish=True
    elif option==47:
        if arg2==4:
            if arg3|arg4|arg5:raw=-22
            else:new[4]=0;publish=True
        elif not valid(arg3) or arg4 or arg5:raw=-22
        elif arg2==1:raw=int(bool(old[4]&(1<<arg3)))
        elif arg2 not in (2,3):raw=-22
        elif arg2==2 and (not old[1]&(1<<arg3) or not old[2]&(1<<arg3) or secure&64):raw=-1
        else:new[4]=(old[4]|(1<<arg3)) if arg2==2 else (old[4]&~(1<<arg3));publish=True
    else:raise ValueError('file prctl option outside reviewed hook domain')
    return raw,new,new_secure,publish

def file_credentials_plan():
    """Exercise scalar UIDs/accounting, restore entry, continue the file session."""
    out=[];permitted=FILE_CAP_INITIAL|64|256|128
    def call(name,n,*args,data=None):out.append(('file_credentials_'+name,dict(number=n,args=list(args)+[0]*(5-len(args))),data))
    def caps(name,e,p=permitted,i=1):call(name,91,0,8,data=[0x20080522,0,e,p,i,0,0,0])
    def res(name,r=UNCHANGED,e=UNCHANGED,saved=UNCHANGED):call(name,147,r,e,saved)
    def re(name,r=UNCHANGED,e=UNCHANGED):call(name,145,r,e)
    def uid(name,value):call(name,146,value)
    def pr(name,*args):call(name,167,*args)
    def ids(name,*args):call(name,148,*(args or (4,8,12)))
    def get(name):call(name,90,0,8,data=[0x20080522,0]+[0xa5a50000+j for j in range(2,8)])
    for index,(name,entry,data) in enumerate(file_prctl_plan()):
        out.append((name,entry,data))
        if index!=19:continue
        uid('invalid_setuid',UNCHANGED)
        caps('gain_setuid',457)
        res('move_accounting_user',9001,1002,0);ids('ids_after_real_change')
        call('real_after_change',174);call('effective_after_change',175)
        re('privileged_root',9002,0);get('caps_after_root')
        call('effective_after_root',175)
        res('drop_effective_root',e=1002);get('caps_after_effective_drop')
        res('foreign_resuid_denied',r=9001)
        re('partial_real_then_effective_denied',1002,9001)
        ids('active_ids_after_partial_abort')
        re('saved_only_real_denied',0)
        uid('unprivileged_real_setuid',9002);ids('real_setuid_ids')
        uid('saved_root_setuid',0);get('caps_after_saved_root')
        res('restore_real_before_keepcaps',1001,0,0)
        pr('keepcaps_on',8,1);pr('ambient_chown',47,2,0)
        res('drop_all_root_keepcaps',9001,9001,9002);get('kept_permitted_caps')
        call('dropped_owner_denied',55,3,9001,UNCHANGED)
        call('dropped_chmod_denied',52,3,0o600)
        call('dropped_noatime_denied',25,3,4,0x40000)
        call('open_pread_after_drop',67,3,8,4,0)
        caps('regain_effective',457)
        uid('privileged_all_ids',9002);ids('privileged_ids')
        re('privileged_real_change',9001,9002)
        pr('suppress_uid_fixup',28,4);pr('ambient_suppressed',47,2,0)
        res('suppressed_root',1001,0,0);get('suppressed_root_caps')
        res('suppressed_nonroot',9001,9002,9001);get('suppressed_caps')
        call('suppressed_transfer',55,3,9001,0);call('suppressed_reclaim',55,3,1002,0)
        pr('enable_uid_fixup',28,0)
        res('root_after_suppression',1001,0,0);get('root_regained_caps')
        re('truncated_noop_real',0x1000003e9,UNCHANGED)
        res('truncated_sentinels',0x1ffffffff,0x1ffffffff,0x1ffffffff)
        res('restore_initial_ids',1001,1002,0);ids('restored_ids')
        caps('restore_entry_caps',1,p=FILE_CAP_INITIAL|64|256,i=0)
        pr('restored_securebits',27);get('restored_caps')
        ids('partial_uid_output',4,UNCHANGED,12)
        ids('aliased_uid_output',4,4,4)
        call('restored_real_query',174);call('restored_effective_query',175)
    return out

def file_rlimit_plan():
    """Query retained limits among the unchanged credential/file session."""
    out=[]
    def query(name,resource,offset=0):
        out.append(('file_rlimit_'+name,dict(number=163,args=[resource,offset,0,0,0]),None))
    markers={'file_credentials_move_accounting_user':'accounting_changed',
             'file_credentials_partial_real_then_effective_denied':'inactive_abort',
             'file_credentials_drop_all_root_keepcaps':'keepcaps_drop',
             'file_credentials_suppressed_nonroot':'suppressed_drop',
             'file_credentials_restore_entry_caps':'restored_entry',
             'table_full':'table_full','last_regular_reference':'last_release'}
    for index,(name,entry,data) in enumerate(file_credentials_plan()):
        out.append((name,entry,data))
        if index==19:
            query('initial_nofile',7);query('initial_nproc',6,8)
            query('end_aligned',7,16);query('unaligned',6,4)
            query('narrow_resource',0x100000007,8)
            query('invalid_resource',16);query('invalid_null',16,UNCHANGED)
            query('invalid_bad_address',UNCHANGED,UNCHANGED-1)
            query('narrow_invalid',0x100000010,16)
            query('null_nofile',7,UNCHANGED);query('bad_nproc',6,UNCHANGED-1)
            query('guard_nofile',7,32);query('partial_nofile',7,24)
            query('partial_nproc',6,24)
        if name in markers:
            query(markers[name]+'_nofile',7);query(markers[name]+'_nproc',6,16)
    query('final_nofile',7);query('final_nproc',6,8)
    return out

def file_limits_plan():
    """All resource queries, interleaved with the established file/credential session."""
    out=[]
    def query(name,resource,offset=0):
        out.append(('file_limits_'+name,dict(number=163,args=[resource,offset,0,0,0]),None))
    markers={'file_rlimit_initial_nproc':'entry','file_rlimit_inactive_abort_nproc':'aborted',
             'file_rlimit_table_full_nofile':'table_full','file_rlimit_last_release_nproc':'released'}
    for name,entry,data in file_rlimit_plan():
        out.append((name,entry,data))
        if name in markers:
            for resource in range(16):query(markers[name]+'_'+str(resource),resource,8*(resource%3))
            if markers[name]=='entry':
                for resource in (0,3,4,8,11,15):query('partial_'+str(resource),resource,24)
                query('narrow_stack',0x100000003,4)
                query('null_stack',3,UNCHANGED);query('guard_core',4,32)
    return out

def file_setrlimit_plan():
    """Mutable NOFILE admission and non-timer limits among the inherited session, plus fd-control's writev and futex
    calls at the same point of the inherited fcntl workload (fd 3 the regular file at position 0)."""
    out=[]
    def call(name,number,args,data=None):
        out.append(('file_setrlimit_'+name,dict(number=number,args=(args+[0]*5)[:5]),data))
    def put(name,resource,soft,hard,offset=0):
        words=[0xa5a50000+j for j in range(8)]
        for j,value in enumerate((soft&0xffffffff,soft>>32,hard&0xffffffff,hard>>32)):
            if offset+4*j in range(0,32,4):words[(offset+4*j)//4]=value
        call(name,164,[resource,offset],words)
    def query(name,resource,offset=0):call(name,163,[resource,offset])
    for name,entry,data in file_limits_plan():
        out.append((name,entry,data))
        if name=='rewind_after_fcntl_alias':
            # Five recorded arguments; a futex call names all six (uaddr2 and val3 zero).
            out+=[(n,dict(number=c['number'],args=(c['args']+[0]*5)[:max(5,len(c['args']))]),d) for n,c,d in vector_futex_calls()]
        if name=='file_limits_entry_15':
            put('lower_nofile',7,4,8);query('read_lower_nofile',7)
            call('dup_denied',23,[0]);call('dup3_denied',24,[0,6,0]);call('fcntl_min_denied',25,[0,0,4])
            call('existing_fd_usable',25,[3,1]);put('restore_nofile',0x100000007,8,8,8)
            call('dup_restored',23,[0]);call('close_restored',57,[4]);query('read_restored_nofile',7,16)
            put('soft_exceeds_hard',7,9,8);put('hard_raise_denied',7,8,9)
            put('invalid_resource',16,4,8);call('invalid_null',164,[16,UNCHANGED])
            call('null_nofile',164,[7,UNCHANGED]);call('bad_pointer',164,[7,UNCHANGED-1]);call('guard_pointer',164,[7,32])
            put('partial_input',7,4,8,24);query('unchanged_after_fault',7)
    put('wide_core',4,0x100000003,UNCHANGED);query('read_wide_core',4,4)
    put('stack_soft',3,4194304,UNCHANGED);query('read_stack_soft',3,8)
    put('lower_memlock_hard',8,2097152,4194304);query('read_memlock_lowered',8,16)
    put('raise_memlock_hard_denied',8,2097152,8388608);query('read_memlock_denied',8)
    put('raise_memlock_soft',8,4194304,4194304,4);query('read_memlock_soft',8,8)
    put('lower_nofile_hard',7,4,5);query('read_nofile_hard',7)
    put('raise_nofile_hard_denied',7,4,8);query('read_nofile_hard_denied',7,16)
    for resource in range(16):query('final_'+str(resource),resource,8*(resource%3))
    return out

def file_capset_step(args,before,initial,pool,active,generation,epochs,fsgids=None,fsuids=None,group_links=None,gids_pool=None,secure_pool=None,uid_pool=None,user_links=None):
    words=before[:];header,data=args[:2]
    read=lambda at:before[at//4] if at in range(0,32,4) else None
    version=read(header);count={0x19980330:1,0x20071026:2,0x20080522:2}.get(version)
    raw=0
    if version is None:raw=-14
    elif count is None:words[header//4]=0x20080522;raw=-22
    elif read(header+4) is None:raw=-14
    elif read(header+4) not in (0,initial['pid']):raw=-1
    elif any(read(data+4*j) is None for j in range(3*count)):raw=-14
    else:
        values=[(read(data+4*j)|((read(data+4*(j+3)) if count==2 else 0)<<32))&((1<<41)-1) for j in range(3)]
        e,p,i=values;old=pool[active];candidate=1-active;pool[candidate]=old[:]
        if secure_pool is not None:secure_pool[candidate]=secure_pool[active]
        if uid_pool is not None:uid_pool[candidate]=uid_pool[active][:];user_links[candidate]=user_links[active][:]
        if fsgids is not None:fsgids[candidate]=fsgids[active]
        if fsuids is not None:fsuids[candidate]=fsuids[active]
        if group_links is not None:group_links[candidate]=group_links[active]
        if gids_pool is not None:gids_pool[candidate]=gids_pool[active][:]
        if (not old[0]&(1<<8) and i&~(old[1]|old[2])) or i&~(old[2]|old[3]) or p&~old[1] or e&~p:raw=-1
        else:
            pool[candidate]=[e,p,i,old[3],old[4]&p&i];active=candidate;generation+=1;epochs[active]=generation
    return raw,words,active,generation

def fd_dup_projection(capture):
    initial=capture['initial'];base,_=projection(dict(initial=initial,profile='minimal'))
    profile=profile_for(capture);positioned=profile in ('file-positioned','fd-control','close-range','fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit')
    metadata=stat_metadata(initial) if profile in ('fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else None;blocks=8;stat_digest=0
    io=profile in ('file-io','file-positioned','fd-control','close-range','fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit');data=list(range(97,113))+[0]*48;size=16;pos=0
    cap_pool=[initial['file_capabilities'][:],initial['file_capabilities'][:]] if profile in ('file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else None
    active=0;generation=0;epochs=[0,0]
    secure_pool=[initial['file_securebits']]*2 if profile in ('file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else None
    uid_pool=[initial['uids'][:],initial['uids'][:]] if profile in ('file-credentials','file-rlimit','file-limits','file-setrlimit') else None
    user_links=[[0,0],[0,0]] if uid_pool is not None else None
    fsgids=[initial['file_fsgid']]*2 if profile in ('file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else None
    fsuids=[initial['file_fsuid']]*2 if profile in ('file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else None
    group_links=[0,0] if profile in ('file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else None
    group_pool=[dict(usage=1,ngroups=1,gid=[0]*4),dict(usage=0,ngroups=0,gid=[0]*4)] if group_links is not None else None
    gids_pool=[initial['gids'][:],initial['gids'][:]] if profile in ('file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else None
    file_status=initial['file_flags'][:] if profile in ('file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else None
    limits=[pair[:] for pair in initial['rlimits']] if profile in ('file-limits','file-setrlimit') else None
    slots=[1,1,1,2,0,0,0,0];clo=8;next_fd=4
    def file():return dict(size=size,pos=pos,bytes=data[:],**(dict(blocks=blocks) if metadata else {}),**(dict(mode=metadata[1]['mode']) if profile in ('fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else {}),**(dict(uid=metadata[1]['uid'],gid=metadata[1]['gid']) if profile in ('fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else {}))
    def snapshot():
        s=dict(slots=slots[:],cloexec=clo,open_fds=sum(1<<i for i,v in enumerate(slots) if v),next_fd=next_fd,counts=[slots.count(1),slots.count(2)])
        if io:s['file']=file()
        if profile in ('fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):s['inode_modes']=[m['mode'] for m in metadata]
        if profile in ('fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):s['inode_owners']=[[m['uid'],m['gid']] for m in metadata]
        if cap_pool is not None:s['file_credentials']=dict(caps=[v[:] for v in cap_pool],active=active,generation=generation,epochs=epochs[:])
        if fsgids is not None:s['file_credentials']['fsgids']=fsgids[:]
        if fsuids is not None:s['file_credentials']['fsuids']=fsuids[:]
        if group_links is not None:s['file_credentials'].update(group_links=group_links[:],group_pool=[dict(p, gid=p['gid'][:]) for p in group_pool])
        if gids_pool is not None:s['file_credentials']['gids']=[g[:] for g in gids_pool]
        if file_status is not None:s['file_status']=file_status[:]
        if secure_pool is not None:s['file_credentials']['securebits']=secure_pool[:]
        if uid_pool is not None:s['file_credentials'].update(uids=[v[:] for v in uid_pool],user_links=[v[:] for v in user_links])
        if profile=='file-setrlimit':s['resource_limits']=[pair[:] for pair in limits]
        return s
    def credential_candidate():
        candidate=1-active;cap_pool[candidate]=cap_pool[active][:];fsgids[candidate]=fsgids[active];fsuids[candidate]=fsuids[active];group_links[candidate]=group_links[active];gids_pool[candidate]=gids_pool[active][:]
        if secure_pool is not None:secure_pool[candidate]=secure_pool[active]
        if uid_pool is not None:uid_pool[candidate]=uid_pool[active][:];user_links[candidate]=user_links[active][:]
        return candidate
    def observed():return [[v,int(bool(clo&(1<<i)))] if v else [0,0] for i,v in enumerate(slots)]
    states=[snapshot()];expected=[]
    plan=[(n,c) for n,c,_ in (file_setrlimit_plan() if profile=='file-setrlimit' else file_limits_plan() if profile=='file-limits' else file_rlimit_plan() if profile=='file-rlimit' else file_credentials_plan() if profile=='file-credentials' else file_prctl_plan() if profile=='file-prctl' else file_capget_plan() if profile=='file-capget' else file_status_plan() if profile=='file-status' else file_group_setters_plan() if profile=='file-group-setters' else file_groups_plan() if profile=='file-groups' else file_fsuid_plan() if profile=='file-fsuid' else file_fsgid_plan() if profile=='file-fsgid' else file_capabilities_plan() if profile=='file-capabilities' else fchown_capable_plan() if profile=='fchown-capable' else fchown_plan() if profile=='fchown' else fchmod_plan() if profile=='fchmod' else fstat_plan() if profile=='fstat' else close_range_plan() if profile=='close-range' else fd_control_plan() if profile=='fd-control' else file_positioned_plan() if positioned else file_io_plan())] if io else fd_dup_plan()
    for ordinal,(_,call) in enumerate(plan):
        n=call['number'];a=[v&0xffffffff for v in call['args']];raw=0
        words=input_words(profile,ordinal) if io else [0xa5a50000+j for j in range(8)]
        if ordinal<len(base):row=dict(base[ordinal]);row['args']=call['args'][:]
        else:
            if n==23:
                old=a[0]
                if old>=8 or not slots[old]:raw=-9
                else:
                    ceiling=limits[7][0] if profile=='file-setrlimit' else 8
                    fd=next((i for i in range(next_fd,ceiling) if not slots[i]),ceiling)
                    if fd==ceiling:raw=-24
                    else:slots[fd]=slots[old];clo&=~(1<<fd);next_fd=fd+1;raw=fd
            elif n==25:
                fd,cmd=a[:2];arg=call['args'][2]
                if fd>=8 or not slots[fd]:raw=-9
                elif cmd==1:raw=int(bool(clo&(1<<fd)))
                elif cmd==2:
                    if arg&1:clo|=1<<fd
                    else:clo&=~(1<<fd)
                elif cmd==3:raw=(file_status if file_status is not None else initial['file_flags'])[slots[fd]-1]
                elif cmd==4 and file_status is not None:
                    if slots[fd]!=2 or arg&(0x4000|0x2000):raise ValueError('file-status flag request outside reviewed memfd contract')
                    flags=arg&0xffffffff;old=file_status[1];mask=0x400|0x800|0x40000
                    if flags&0x40000 and not old&0x40000 and metadata[1]['uid']!=fsuids[active] and not cap_pool[active][0]&8:raw=-1
                    else:file_status[1]=(old&~mask)|(flags&mask)
                elif cmd in (0,1030):
                    start=arg&0xffffffff
                    if start>=(limits[7][0] if profile=='file-setrlimit' else 8):raw=-22
                    else:
                        ceiling=limits[7][0] if profile=='file-setrlimit' else 8
                        target=next((i for i in range(max(start,next_fd),ceiling) if not slots[i]),ceiling)
                        if target==ceiling:raw=-24
                        else:
                            slots[target]=slots[fd];raw=target
                            if start<=next_fd:next_fd=target+1
                            if cmd==1030:clo|=1<<target
                            else:clo&=~(1<<target)
                else:raw=-22
            elif n==24:
                old,new,flags=a[:3]
                if flags&~0x80000 or old==new:raw=-22
                elif new>=(limits[7][0] if profile=='file-setrlimit' else 8) or old>=8 or not slots[old]:raw=-9
                else:
                    slots[new]=slots[old];raw=new
                    if flags&0x80000:clo|=1<<new
                    else:clo&=~(1<<new)
            elif n==57:
                fd=a[0]
                if fd>=8 or not slots[fd]:raw=-9
                else:slots[fd]=0;next_fd=min(next_fd,fd)
            elif n==436:
                first,last,flags=a[:3]
                if flags&~6 or first>last:raw=-22
                elif flags&2:raise ValueError('close_range unshare is outside the admitted recipe')
                elif flags&4:
                    for fd in range(first,min(last,63)+1):clo|=1<<fd
                else:
                    for fd in range(first,min(last,63)+1):
                        if fd<8 and slots[fd]:slots[fd]=0;next_fd=min(next_fd,fd)
            elif n==164:
                resource=a[0];offset=call['args'][1]
                if offset not in range(0,17,4):raw=-14
                elif resource>=16:raw=-22
                else:
                    values=[words[offset//4+j]|(words[offset//4+j+1]<<32) for j in (0,2)]
                    if values[0]>values[1]:raw=-22
                    elif resource==7 and values[1]>8:raw=-1
                    elif values[1]>limits[resource][1] and not cap_pool[active][0]&(1<<24):raw=-1
                    elif resource not in (3,4,7,8):raise ValueError('resource update outside non-timer recipe')
                    else:limits[resource]=values
            elif n==163:
                resource=a[0]
                if resource>=16:raw=-22
                elif profile not in ('file-limits','file-setrlimit') and resource not in (6,7):raise ValueError('getrlimit resource outside reviewed query contract')
                else:
                    payload=limits[resource] if profile in ('file-limits','file-setrlimit') else (initial['nproc_limit'] if resource==6 else initial['nofile_limit'])
                    values=[part for value in payload for part in (value&0xffffffff,value>>32)]
                    for j,value in enumerate(values):
                        at=call['args'][1]+4*j
                        if at not in range(0,32,4):raw=-14;break
                        words[at//4]=value
            elif n==90:
                cap_header,cap_data=call['args'][:2]
                def read_cap(at):return words[at//4] if at in range(0,32,4) else None
                version=read_cap(cap_header);count={0x19980330:1,0x20071026:2,0x20080522:2}.get(version)
                null_output=cap_data==UNCHANGED
                if version is None:raw=-14
                elif count is None:
                    words[cap_header//4]=0x20080522;raw=0 if null_output else -22
                elif null_output:raw=0
                elif read_cap(cap_header+4) is None:raw=-14
                elif read_cap(cap_header+4)&0x80000000:raw=-22
                elif read_cap(cap_header+4) not in (0,initial['pid']):raw=-3
                else:
                    e,p,i=cap_pool[active][:3];payload=[e&0xffffffff,p&0xffffffff,i&0xffffffff,e>>32,p>>32,i>>32]
                    for j,v in enumerate(payload[:3*count]):
                        at=cap_data+4*j
                        if at not in range(0,32,4):raw=-14;break
                        words[at//4]=v
            elif n==91:
                raw,words,active,generation=file_capset_step(call['args'],words,initial,cap_pool,active,generation,epochs,fsgids,fsuids,group_links,gids_pool,secure_pool,uid_pool,user_links)
            elif n==167:
                raw,new,new_secure,publish=file_prctl_update(call['args'],cap_pool[active],secure_pool[active])
                if publish:
                    candidate=credential_candidate();cap_pool[candidate]=new;secure_pool[candidate]=new_secure
                    active=candidate;generation+=1;epochs[active]=generation
            elif n==158:
                p=group_pool[group_links[active]];group_count=a[0];raw=p['ngroups']
                if group_count&0x80000000 or (group_count and group_count<p['ngroups']):raw=-22
                elif group_count:
                    for j,value in enumerate(p['gid'][:p['ngroups']]):
                        at=call['args'][1]+4*j
                        if at not in range(0,32,4):raw=-14;break
                        words[at//4]=value
            elif n==159:
                group_count=a[0]
                if not cap_pool[active][0]&64:raw=-1
                elif group_count>65536:raw=-22
                else:
                    if group_count>4:raise ValueError('file supplementary-group allocation exceeds capacity')
                    index=next(j for j,p in enumerate(group_pool) if p['usage']==0);p=group_pool[index];p.update(usage=1,ngroups=group_count,gid=[0]*4)
                    for j in range(group_count):
                        at=call['args'][1]+4*j
                        if at not in range(0,32,4):raw=-14;break
                        value=words[at//4]
                        if value==0xffffffff:raw=-22;break
                        p['gid'][j]=value
                    if raw:p['usage']=0
                    else:
                        p['gid'][:group_count]=sorted(p['gid'][:group_count]);group_pool[group_links[active]]['usage']-=1
                        candidate=1-active;cap_pool[candidate]=cap_pool[active][:];fsgids[candidate]=fsgids[active];fsuids[candidate]=fsuids[active];group_links[candidate]=index
                        if secure_pool is not None:secure_pool[candidate]=secure_pool[active]
                        if uid_pool is not None:uid_pool[candidate]=uid_pool[active][:];user_links[candidate]=user_links[active][:]
                        if gids_pool is not None:gids_pool[candidate]=gids_pool[active][:]
                        active=candidate;generation+=1;epochs[active]=generation
            elif n==151:
                uid=a[0];raw=fsuids[active]
                if uid!=0xffffffff:
                    candidate=1-active;cap_pool[candidate]=cap_pool[active][:];fsgids[candidate]=fsgids[active];fsuids[candidate]=fsuids[active]
                    if secure_pool is not None:secure_pool[candidate]=secure_pool[active]
                    if uid_pool is not None:uid_pool[candidate]=uid_pool[active][:];user_links[candidate]=user_links[active][:]
                    if group_links is not None:group_links[candidate]=group_links[active]
                    if gids_pool is not None:gids_pool[candidate]=gids_pool[active][:]
                    if uid in (uid_pool[active] if uid_pool is not None else initial['uids'])+[fsuids[active]] or cap_pool[active][0]&(1<<7):
                        if uid!=fsuids[active]:
                            old=fsuids[active];fsuids[candidate]=uid
                            if old==0 and uid!=0 and (secure_pool is None or not secure_pool[active]&4):cap_pool[candidate][0]&=~FS_CAPS
                            if old!=0 and uid==0 and (secure_pool is None or not secure_pool[active]&4):cap_pool[candidate][0]|=cap_pool[candidate][1]&FS_CAPS
                            active=candidate;generation+=1;epochs[active]=generation
            elif n in (145,146,147):
                values=a[:3] if n==147 else a[:2];old=uid_pool[active];privileged=bool(cap_pool[active][0]&128)
                def uid_fixup(candidate):
                    new=uid_pool[candidate];user_links[candidate]=[[1001,0,9001,9002].index(new[0])]*2
                    fsuids[candidate]=new[1]
                    if not secure_pool[active]&4:
                        if 0 in old and 0 not in new:
                            if not secure_pool[active]&16:cap_pool[candidate][0]=cap_pool[candidate][1]=0
                            cap_pool[candidate][4]=0
                        if old[1]==0 and new[1]!=0:cap_pool[candidate][0]=0
                        if old[1]!=0 and new[1]==0:cap_pool[candidate][0]=cap_pool[candidate][1]
                if n==147:
                    noop=all(v==0xffffffff or (v==old[j] and (j!=1 or v==fsuids[active])) for j,v in enumerate(values))
                    if not noop:
                        if any(v!=0xffffffff and v not in old for v in values) and not privileged:raw=-1
                        else:
                            candidate=credential_candidate();uid_pool[candidate]=[old[j] if v==0xffffffff else v for j,v in enumerate(values)];uid_fixup(candidate)
                            active=candidate;generation+=1;epochs[active]=generation
                elif n==146 and values[0]==0xffffffff:raw=-22
                else:
                    candidate=credential_candidate();new=uid_pool[candidate]
                    if n==146:
                        value=values[0]
                        if privileged:new[0]=new[2]=value
                        elif value not in (old[0],old[2]):raw=-1
                        if not raw:new[1]=value
                    else:
                        real,effective=values
                        if real!=0xffffffff:
                            new[0]=real
                            if real not in old[:2] and not privileged:raw=-1
                        if not raw and effective!=0xffffffff:
                            new[1]=effective
                            if effective not in old and not privileged:raw=-1
                        if not raw and (real!=0xffffffff or (effective!=0xffffffff and effective!=old[0])):new[2]=new[1]
                    if not raw:
                        uid_fixup(candidate);active=candidate;generation+=1;epochs[active]=generation
            elif n==174:raw=(uid_pool[active] if uid_pool is not None else initial['uids'])[0]
            elif n==175:raw=(uid_pool[active] if uid_pool is not None else initial['uids'])[1]
            elif n==148:
                for value,at in zip(uid_pool[active],call['args'][:3]):
                    if at not in range(0,32,4):raw=-14;break
                    words[at//4]=value
            elif n==152:
                gid=a[0];raw=fsgids[active]
                if gid!=0xffffffff:
                    candidate=1-active;cap_pool[candidate]=cap_pool[active][:];fsgids[candidate]=fsgids[active]
                    if secure_pool is not None:secure_pool[candidate]=secure_pool[active]
                    if uid_pool is not None:uid_pool[candidate]=uid_pool[active][:];user_links[candidate]=user_links[active][:]
                    if fsuids is not None:fsuids[candidate]=fsuids[active]
                    if group_links is not None:group_links[candidate]=group_links[active]
                    if gids_pool is not None:gids_pool[candidate]=gids_pool[active][:]
                    if gid in (gids_pool[active] if gids_pool is not None else initial['gids'])+[fsgids[active]] or cap_pool[active][0]&(1<<6):
                        if gid!=fsgids[active]:
                            fsgids[candidate]=gid;active=candidate;generation+=1;epochs[active]=generation
            elif n in (143,144,149):
                old=gids_pool[active];privileged=bool(cap_pool[active][0]&64)
                if n==149:
                    values=a[:3];same=all(v==0xffffffff or (v==old[j] and (j!=1 or v==fsgids[active])) for j,v in enumerate(values))
                    if not same:
                        if any(v!=0xffffffff and v not in old for v in values) and not privileged:raw=-1
                        else:
                            candidate=credential_candidate();gids_pool[candidate]=[old[j] if v==0xffffffff else v for j,v in enumerate(values)];fsgids[candidate]=gids_pool[candidate][1]
                            active=candidate;generation+=1;epochs[active]=generation
                elif n==144:
                    value=a[0]
                    if value==0xffffffff:raw=-22
                    else:
                        candidate=credential_candidate()
                        if privileged:gids_pool[candidate]=[value]*3;fsgids[candidate]=value
                        elif value in (old[0],old[2]):gids_pool[candidate][1]=value;fsgids[candidate]=value
                        else:raw=-1
                        if not raw:active=candidate;generation+=1;epochs[active]=generation
                else:
                    real,effective=a[:2];candidate=credential_candidate();new=gids_pool[candidate]
                    if real!=0xffffffff:
                        if real in old[:2] or privileged:new[0]=real
                        else:raw=-1
                    if not raw and effective!=0xffffffff:
                        if effective in old or privileged:new[1]=effective
                        else:raw=-1
                    if not raw:
                        if real!=0xffffffff or (effective!=0xffffffff and effective!=old[0]):new[2]=new[1]
                        fsgids[candidate]=new[1];active=candidate;generation+=1;epochs[active]=generation
            elif n==176:raw=gids_pool[active][0]
            elif n==177:raw=gids_pool[active][1] if gids_pool is not None else initial['gids'][1]
            elif n==150:
                for value,at in zip(gids_pool[active],call['args'][:3]):
                    if at not in range(0,32,4):raw=-14;break
                    words[at//4]=value
            elif n==55:
                fd,uid,gid=a[:3]
                if fd>=8 or not slots[fd]:raw=-9
                else:
                    at=metadata[slots[fd]-1];owner=at['uid']==(fsuids[active] if fsuids is not None else initial['uids'][1])
                    if not (cap_pool[active][0] if cap_pool is not None else initial['ownership_effective_caps'])&1 and uid!=0xffffffff and (not owner or uid!=at['uid']):raw=-1
                    elif not (cap_pool[active][0] if cap_pool is not None else initial['ownership_effective_caps'])&1 and gid!=0xffffffff and (not owner or gid not in [at['gid'],fsgids[active] if fsgids is not None else initial['gids'][1]]+(group_pool[group_links[active]]['gid'][:group_pool[group_links[active]]['ngroups']] if group_links is not None else initial['owner_groups'])):raw=-1
                    else:
                        if uid!=0xffffffff:at['uid']=uid
                        if gid!=0xffffffff:at['gid']=gid
            elif n==52:
                fd=a[0]
                if fd>=8 or not slots[fd]:raw=-9
                elif metadata[slots[fd]-1]['uid']!=(fsuids[active] if fsuids is not None else initial['uids'][1]) and not (cap_pool is not None and cap_pool[active][0]&8):raw=-1
                else:
                    mode=call['args'][1]&0xffff
                    if mode&0o7000:raise ValueError('special chmod bits are outside the admitted recipe')
                    metadata[slots[fd]-1]['mode']=(metadata[slots[fd]-1]['mode']&~0o7777)|(mode&0o7777)
            elif n==80:
                fd=a[0];offset=call['args'][1]
                statbuf=bytearray().join(v.to_bytes(4,'little') for v in stat_input_words())
                if fd>=8 or not slots[fd]:raw=-9
                else:
                    at=metadata[slots[fd]-1];payload=stat_bytes(at,size if slots[fd]==2 else 0,blocks if slots[fd]==2 else at['blocks'])
                    copied=min(128,128-offset) if offset in range(128) else 0
                    if copied:statbuf[offset:offset+copied]=payload[:copied]
                    raw=0 if copied==128 else -14
                statwords=[int.from_bytes(statbuf[j:j+4],'little') for j in range(0,128,4)]
            elif n==46:
                fd=a[0];length=call['args'][1];length=length if length<1<<63 else length-(1<<64)
                if length<0:raw=-22
                elif fd>=8 or not slots[fd]:raw=-9
                elif slots[fd]!=2:raw=-22
                elif length>64:raise ValueError('truncate capacity exceeded by recipe')
                else:
                    data[length:]=[0]*(64-length);size=length
                    if not length:blocks=0
            elif n in (62,63,64,67,68):
                fd=a[0]
                at=call['args'][3] if n in (67,68) else pos
                if n in (67,68) and at>=1<<63:raw=-22
                elif fd>=8 or not slots[fd]:raw=-9
                elif slots[fd]!=2:
                    if n in (67,68):raw=-29
                    else:raise ValueError('console I/O is outside the admitted recipe')
                elif n==62:
                    offset=call['args'][1];offset=offset if offset<1<<63 else offset-(1<<64)
                    whence=a[2]
                    if whence>4:raw=-22
                    elif whence in (3,4):raise ValueError('data/hole seek is outside the admitted recipe')
                    else:
                        target=offset+(pos if whence==1 else size if whence==2 else 0)
                        if target<0 or target>0x7fffffffffffffff:raw=-22
                        else:pos=target;raw=pos
                else:
                    offset,count=call['args'][1:3];writing=n in (64,68)
                    if count>1<<48:raw=-14
                    elif not count or (not writing and at>=size):raw=0
                    else:
                        if writing and file_status is not None and file_status[1]&0x400:at=size
                        length=count if writing else min(count,size-at)
                        available=32-offset if offset in range(32) else 0
                        copied=min(length,available)
                        if not copied:raw=-14
                        else:
                            memory=bytearray().join(v.to_bytes(4,'little') for v in words)
                            if writing:
                                if at+copied>64:raise ValueError('file capacity exceeded by recipe')
                                data[at:at+copied]=memory[offset:offset+copied];size=max(size,at+copied);blocks=8
                            else:
                                memory[offset:offset+copied]=bytes(data[at:at+copied]);words=[int.from_bytes(memory[j:j+4],'little') for j in range(0,32,4)]
                            if n in (63,64):pos=at+copied
                            raw=copied
            elif n==66:
                # do_writev: fdget_pos (EBADF), vfs_writev (FMODE_WRITE, then import_iovec: more than UIO_MAXIOV
                # segments or a negative length is EINVAL), then the gathered bytes at the file position.
                fd=a[0];iov=call['args'][1];vlen=call['args'][2]
                if fd>=8 or not slots[fd]:raw=-9
                elif slots[fd]!=2:raise ValueError('console I/O is outside the admitted recipe')
                elif vlen>1024:raw=-22
                elif not vlen:raw=0
                else:
                    memory=bytearray().join(v.to_bytes(4,'little') for v in words);segments=[]
                    for k in range(vlen):
                        at_entry=iov+16*k
                        if at_entry+16>32:raise ValueError('iovec outside the admitted buffer')
                        segments.append((int.from_bytes(memory[at_entry:at_entry+8],'little'),int.from_bytes(memory[at_entry+8:at_entry+16],'little')))
                    if any(length>=1<<63 for _,length in segments):raw=-22
                    else:
                        if any(b+l>32 for b,l in segments):raise ValueError('iovec segment outside the admitted buffer')
                        gathered=b''.join(bytes(memory[b:b+l]) for b,l in segments);at=pos
                        if file_status is not None and file_status[1]&0x400:at=size
                        if at+len(gathered)>64:raise ValueError('file capacity exceeded by recipe')
                        data[at:at+len(gathered)]=gathered;size=max(size,at+len(gathered));blocks=8
                        pos=at+len(gathered);raw=len(gathered)
            elif n==98:
                # do_futex: an unknown command is ENOSYS; FUTEX_WAKE and FUTEX_WAIT key the word (unaligned: EINVAL).
                # A private wake finds no waiter (0); a wait on a changed value returns EAGAIN. A wait on the word's own
                # value would block, which the recipe never asks.
                offset=call['args'][0];op=a[1];value=a[2];cmd=op&~(128|256)
                if cmd not in (0,1):raw=-38
                elif offset%4:raw=-22
                elif offset not in range(0,32,4):raise ValueError('futex word outside the admitted buffer')
                elif cmd==1:raw=0
                elif words[offset//4]==value:raise ValueError('a blocking futex wait is outside the admitted recipe')
                else:raw=-11
            else:raise ValueError('unsupported fd recipe operation')
            row=dict(**call,raw_bits=raw&UNCHANGED,words=words,umask_after=base[-1]['umask_after'])
            # The native record keeps CAPTURE_ARGUMENTS arguments (five for the prctl-capable file profiles, else four); a
            # futex recipe's trailing uaddr2 and val3 are zero, which the slice adapter requires of every call.
            width=5 if profile in ('file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else 4
            if len(row['args'])>width:
                if any(row['args'][width:]):raise ValueError('a recorded call has a nonzero argument beyond the capture width')
                row['args']=row['args'][:width]
        if io:row.update(input_words=input_words(profile,ordinal),file_after=file() if 2 in slots else None)
        if metadata:
            row['stat_words']=statwords if n==80 else stat_input_words()
            if n==80 and not raw:
                for v in statwords:stat_digest=((stat_digest*1099511628211)^v)&UNCHANGED
            row['stat_digest']=stat_digest
        if cap_pool is not None:row['file_caps_after']=cap_pool[active][:3]
        if fsgids is not None:row['file_fsgid_after']=fsgids[active]
        if fsuids is not None:row['file_fsuid_after']=fsuids[active]
        if group_links is not None:row['file_groups_after']=group_pool[group_links[active]]['gid'][:group_pool[group_links[active]]['ngroups']]
        if gids_pool is not None:row['file_gids_after']=gids_pool[active][:]
        if file_status is not None:row['fd_status_after']=[file_status[v-1] if v else None for v in slots]
        if secure_pool is not None:row['file_prctl_after']=cap_pool[active][3:]+[secure_pool[active]]
        if uid_pool is not None:row['file_uids_after']=uid_pool[active][:]
        if profile in ('file-rlimit','file-limits','file-setrlimit'):row['file_rlimits_after']=[limits[6][:],limits[7][:]] if profile=='file-setrlimit' else [initial['nproc_limit'][:],initial['nofile_limit'][:]]
        if profile in ('file-limits','file-setrlimit'):row['file_all_rlimits_after']=[pair[:] for pair in limits]
        row['fds_after']=observed();expected.append(row);states.append(snapshot())
    return expected,states

FD_HELPERS=[('find_next_fd','static unsigned int'),('alloc_fd','static int'),('__get_unused_fd_flags','int'),('get_unused_fd_flags','int'),('__put_unused_fd','static void'),('fd_install','void'),('file_close_fd_locked','struct file *'),('file_close_fd','struct file *'),('__fget_files_rcu','static inline struct file *'),('__fget_files','static struct file *'),('__fget','static inline struct file *'),('fget_raw','struct file *'),('do_dup2','static int'),('ksys_dup3','static int')]
IO_HELPERS=[('unsigned_offsets','static inline bool'),('vfs_setpos','loff_t'),('generic_file_llseek_size','loff_t'),('ksys_lseek','static off_t'),('rw_verify_area','int'),('file_ppos','static inline loff_t *'),('ksys_read','ssize_t'),('ksys_write','ssize_t')]

def digest(data):return hashlib.sha256(data).hexdigest()

# Kernel source excerpts live once, in a content-addressed store (excerpts/<sha256>). A root (a profile, a native
# capture, a bundle's native/) lists its excerpts in excerpts.json (path -> sha256); upstream(root) is the directory
# readers use: root/upstream, materialized from the store and verified file by file, rebuilt when the manifest
# changes (a stamp records which manifest it was built from). A root without a manifest keeps its own upstream/.
# Files edited in a materialized directory return to the store with ingest(root).
EXCERPT_STORE=Path(__file__).resolve().parent/'excerpts'
EXCERPT_MANIFEST='excerpts.json'
EXCERPT_STAMP='.excerpts'
def _excerpt_digest(data):return hashlib.sha256(data).hexdigest()
def excerpt_manifest(root):
    path=Path(root)/EXCERPT_MANIFEST
    if not path.exists():return None
    manifest=json.loads(path.read_text())
    if manifest.get('format')!='osrec-kernel-excerpts-v1' or not isinstance(manifest.get('files'),dict):raise ValueError('invalid kernel excerpt manifest '+str(path))
    for name,sha in manifest['files'].items():
        if not re.fullmatch(r'[0-9a-f]{64}',sha) or name.startswith('/') or '..' in Path(name).parts:raise ValueError('invalid kernel excerpt entry '+name)
    return manifest
def upstream(root):
    """The directory of a root's kernel source excerpts (materialized from the store when the root has a manifest)."""
    root=Path(root);directory=root/'upstream';manifest=excerpt_manifest(root)
    if manifest is None:return directory
    stamp=_excerpt_digest(json.dumps(manifest['files'],sort_keys=True).encode())
    if (directory/EXCERPT_STAMP).exists() and (directory/EXCERPT_STAMP).read_text()==stamp:return directory
    staging=root/('.upstream-%d'%__import__('os').getpid())
    shutil.rmtree(staging,ignore_errors=True)
    for name,sha in sorted(manifest['files'].items()):
        data=(EXCERPT_STORE/sha).read_bytes()
        if _excerpt_digest(data)!=sha:raise ValueError('kernel excerpt store entry is corrupt: '+sha)
        (staging/name).parent.mkdir(parents=True,exist_ok=True);(staging/name).write_bytes(data)
    staging.mkdir(exist_ok=True);(staging/EXCERPT_STAMP).write_text(stamp)
    shutil.rmtree(directory,ignore_errors=True);staging.rename(directory)
    return directory
def ingest(root):
    """Store every file of root/upstream and write root's manifest (a materialized directory may have been edited)."""
    root=Path(root);directory=root/'upstream';files={}
    for path in sorted(p for p in directory.rglob('*') if p.is_file() and p.name!=EXCERPT_STAMP):
        data=path.read_bytes();sha=_excerpt_digest(data);target=EXCERPT_STORE/sha
        if not target.exists():EXCERPT_STORE.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
        files[path.relative_to(directory).as_posix()]=sha
    manifest=dict(format='osrec-kernel-excerpts-v1',files=files)
    (root/EXCERPT_MANIFEST).write_text(json.dumps(manifest,indent=1,sort_keys=True)+'\n')
    (directory/EXCERPT_STAMP).write_text(_excerpt_digest(json.dumps(files,sort_keys=True).encode()))
    return manifest
def copy_excerpts(source,target):
    """Give `target` the same excerpts as `source`: its manifest when it has one, else a copy of its upstream/."""
    source,target=Path(source),Path(target)
    if excerpt_manifest(source) is not None:shutil.copyfile(source/EXCERPT_MANIFEST,target/EXCERPT_MANIFEST)
    else:shutil.copytree(source/'upstream',target/'upstream')

# fd-control sources below the descriptor and read/write entries, and the
# original helpers each contributes, with their exact v6.10 declarations. A
# static callee of a reviewed dispatch model is extracted without `static`.
FD_CONTROL_SOURCES=[
    ('include/linux/file.h',[('fdput','static inline void'),('__to_fd','static inline struct fd'),('fdget','static inline struct fd'),('fdget_raw','static inline struct fd'),('fdget_pos','static inline struct fd'),('fdput_pos','static inline void')]),
    ('include/linux/fdtable.h',[('files_lookup_fd_raw','static inline struct file *')]),
    ('include/linux/dcache.h',[('d_inode','static inline struct inode *'),('d_backing_inode','static inline struct inode *')]),
    ('include/linux/fs.h',[('init_sync_kiocb', 'static inline void'), ('file_start_write', 'static inline void'), ('file_end_write', 'static inline void'), ('i_size_read', 'static inline loff_t'), ('file_accessed', 'static inline void'), ('mapping_writably_mapped', 'static inline int'), ('inode_get_atime', 'static inline struct timespec64'), ('inode_get_mtime', 'static inline struct timespec64'), ('inode_get_ctime', 'static inline struct timespec64'), ('inode_set_atime_to_ts', 'static inline struct timespec64'), ('inode_set_mtime_to_ts', 'static inline struct timespec64'), ('inode_set_ctime_to_ts', 'static inline struct timespec64'), ('i_user_ns', 'static inline struct user_namespace *'), ('i_uid_into_vfsuid', 'static inline vfsuid_t'), ('i_gid_into_vfsgid', 'static inline vfsgid_t'), ('HAS_UNMAPPED_ID', 'static inline bool'), ('inode_unhashed', 'static inline int'), ('i_size_write', 'static inline void'), ('file_dentry', 'static inline struct dentry *'), ('inode_lock', 'static inline void'), ('inode_unlock', 'static inline void'), ('file_mnt_idmap', 'static inline struct mnt_idmap *'), ('i_uid_needs_update', 'static inline bool'), ('i_gid_needs_update', 'static inline bool'), ('i_uid_update', 'static inline void'), ('i_gid_update', 'static inline void'), ('inode_is_locked', 'static inline int'), ('kiocb_set_rw_flags', 'static inline int'), ('__sb_end_write', 'static inline void'), ('__sb_start_write', 'static inline void'), ('__sb_start_write_trylock', 'static inline bool'), ('sb_end_write', 'static inline void'), ('sb_start_write', 'static inline void'), ('sb_start_write_trylock', 'static inline bool')]),
    ('include/linux/uio.h',[('iov_iter_ubuf','static inline void'),('iov_iter_type','static inline enum iter_type'),('iter_is_ubuf','static inline bool'),('iter_is_iovec','static inline bool'),('user_backed_iter','static inline bool'),('iov_iter_count','static inline size_t'),('iov_iter_truncate','static inline void'),('iov_iter_is_discard','static inline bool'),('iov_iter_is_xarray','static inline bool'),('iov_iter_is_bvec','static inline bool'),('iter_iov','static inline const struct iovec *'),('iov_iter_is_kvec','static inline bool')]),
    ('include/linux/fsnotify_backend.h',[('fsnotify_sb_info','static inline struct fsnotify_sb_info *')]),
    ('include/linux/fsnotify.h',[('fsnotify_sb_has_priority_watchers','static inline bool'),('fsnotify_sb_has_watchers','static inline bool'),('fsnotify_parent','static inline int'),('fsnotify_file','static inline int'),('fsnotify_access','static inline void'),('fsnotify_modify','static inline void'),('fsnotify_dentry','static inline void'),('fsnotify_change','static inline void')]),
    ('include/linux/sched/xacct.h',[('add_rchar','static inline void'),('add_wchar','static inline void'),('inc_syscr','static inline void'),('inc_syscw','static inline void')]),
    ('include/linux/list.h',[('hlist_unhashed','static inline int'),('list_empty','static inline int')]),
    ('include/linux/time64.h',[('timespec64_equal','static inline int'),('timespec64_compare','static inline int'),('timespec64_valid','static inline bool')]),
    ('include/linux/ktime.h',[('ktime_set','static inline ktime_t'),('timespec64_to_ktime','static inline ktime_t')]),
    ('include/linux/hrtimer.h',[('hrtimer_set_expires_range_ns','static inline void'),('destroy_hrtimer_on_stack','static inline void')]),
    ('include/linux/time_namespace.h',[('timens_ktime_to_host','static inline ktime_t')]),
    ('kernel/time/hrtimer.c',[('ktime_add_safe','ktime_t'),('hrtimer_clockid_to_base','static inline int'),('__hrtimer_init','static void'),('hrtimer_try_to_cancel','int'),('hrtimer_cancel','int'),('__hrtimer_init_sleeper','static void'),('hrtimer_init_sleeper_on_stack','void'),('hrtimer_active','bool')]),
    ('include/linux/thread_info.h',[('check_copy_size','static __always_inline __must_check bool')]),
    ('include/linux/uaccess.h',[('_copy_from_user','static inline __must_check unsigned long'),('copy_from_user','static __always_inline unsigned long __must_check')]),
    ('kernel/time/time.c',[('get_timespec64','int')]),
    ('include/linux/iversion.h',[('inode_peek_iversion_raw','static inline u64'),('inode_iversion_need_inc','static inline bool'),('inode_inc_iversion','static inline void')]),
    ('include/linux/quotaops.h',[('is_quota_modification','static inline bool')]),
    ('include/linux/filelock.h',[('break_deleg','static inline int'),('try_break_deleg','static inline int'),('locks_inode_context','static inline struct file_lock_context *')]),
    ('include/linux/pagevec.h',[('folio_batch_init','static inline void'),('folio_batch_count','static inline unsigned int'),('folio_batch_space','static inline unsigned int'),('folio_batch_add','static inline unsigned'),('folio_batch_release','static inline void')]),
    ('include/linux/highmem.h',[('folio_zero_range','static inline void')]),
    ('include/linux/mount.h',[('mnt_idmap','static inline struct mnt_idmap *')]),
    ('include/linux/mnt_idmapping.h',[('__vfsuid_val','static inline uid_t'),('__vfsgid_val','static inline gid_t'),('vfsuid_valid','static inline bool'),('vfsgid_valid','static inline bool')]),
    ('include/linux/xarray.h',[('xa_mk_internal','static inline void *'),('xa_to_internal','static inline unsigned long'),('xa_is_internal','static inline bool'),('xa_is_value','static inline bool'),('xa_is_zero','static inline bool'),('xa_is_err','static inline bool'),('xa_err','static inline int'),('xa_head','static inline void *'),('xa_entry','static inline void *'),('xa_is_node','static inline bool'),('xa_to_node','static inline struct xa_node *'),('xa_mk_sibling','static inline void *'),('xa_is_sibling','static inline bool'),('xa_to_sibling','static inline unsigned long'),('xa_is_retry','static inline bool'),('xas_error','static inline int'),('xas_invalid','static inline bool'),('xas_valid','static inline bool'),('xas_reset','static inline void'),('xas_retry','static inline bool'),('xas_reload','static inline void *'),('xa_parent','static inline struct xa_node *'),('xas_not_node','static inline bool')]),
    ('include/linux/pagemap.h',[('mapping_gfp_mask','static inline gfp_t'),('folio_file_page','static inline struct page *'),('folio_trylock','static inline bool'),('folio_lock','static inline void'),('folio_index','static inline pgoff_t'),('folio_contains','static inline bool'),('folio_next_index','static inline pgoff_t')]),
    ('include/linux/mm.h',[('folio_put','static inline void')]),
    ('lib/xarray.c',[('set_bounds','static void *'),('get_offset','static unsigned int'),('xas_descend','static __always_inline void *'),('xas_start','static void *'),('xas_load','void *'),('xas_move_index','static void'),('xas_next_offset','static void'),('xas_find','void *')]),
    ('lib/iov_iter.c',[('page_copy_sane','static inline bool'),('copy_page_to_iter','size_t'),('fault_in_iov_iter_readable','size_t'),('copy_page_from_iter_atomic','size_t'),('iov_iter_revert','void'),('copy_to_user_iter','static __always_inline size_t'),('copy_from_user_iter','static __always_inline size_t'),('memcpy_to_iter','static __always_inline size_t'),('memcpy_from_iter','static __always_inline size_t'),('_copy_to_iter','size_t'),('__copy_from_iter','static __always_inline size_t'),('iov_iter_init','void'),('copy_iovec_from_user','static __noclone int'),('iovec_from_user','struct iovec *'),('__import_iovec_ubuf','static ssize_t'),('__import_iovec','ssize_t'),('import_iovec','ssize_t'),('import_ubuf','int'),('iov_iter_iovec_advance','static void'),('iov_iter_advance','void')]),
    ('include/linux/iov_iter.h',[('iterate_ubuf','static __always_inline size_t'),('iterate_iovec','static __always_inline size_t'),('iterate_and_advance2','static __always_inline size_t'),('iterate_and_advance','static __always_inline size_t')]),
    ('include/linux/fault-inject-usercopy.h',[('should_fail_usercopy','static inline bool')]),
    ('include/linux/bitops.h',[('sign_extend64','static __always_inline __s64'),('rol32','static inline __u32'),('sign_extend32','static __always_inline __s32')]),
    ('include/linux/jhash.h',[('jhash2','static inline u32')]),
    ('kernel/futex/futex.h',[('futex_to_flags','static inline unsigned int'),('should_fail_futex','static inline bool'),('futex_match','static inline int'),('futex_hb_waiters_inc','static inline void'),('futex_hb_waiters_dec','static inline void'),('futex_hb_waiters_pending','static inline int'),('double_lock_hb','static inline void'),('double_unlock_hb','static inline void')]),
    ('kernel/futex/core.c',[('futex_hash','struct futex_hash_bucket *'),('futex_setup_timer','struct hrtimer_sleeper *'),('get_futex_key','int'),('futex_get_value_locked','int'),('futex_q_lock','struct futex_hash_bucket *'),('futex_q_unlock','void'),('futex_top_waiter','struct futex_q *'),('futex_cmpxchg_value_locked','int')]),
    ('include/linux/page-flags.h',[('folio_test_anon','static __always_inline bool')]),
    ('kernel/futex/pi.c',[('refill_pi_state_cache','int'),('lock_pi_update_atomic','static int'),('futex_lock_pi_atomic','int'),('futex_lock_pi','int'),('futex_unlock_pi','int')]),
    ('kernel/futex/waitwake.c',[('futex_wake','int'),('futex_wait_setup','int'),('__futex_wait','int'),('futex_wait','int'),('futex_atomic_op_inuser','static int'),('futex_wake_op','int')]),
    ('kernel/futex/requeue.c',[('futex_requeue','int')]),
    ('arch/arm64/include/asm/futex.h',[('arch_futex_atomic_op_inuser','static inline int')]),
    ('kernel/sched/core.c',[('wake_up_q','void')]),
    ('include/asm-generic/access_ok.h',[('__access_ok','static inline int')]),
    ('arch/arm64/include/asm/uaccess.h',[('access_ok','static inline int'),('uaccess_ttbr0_disable','static inline bool'),('uaccess_ttbr0_enable','static inline bool')]),
    ('mm/gup.c',[('fault_in_readable','size_t'),('gup_fast_permitted','static bool'),('try_get_folio','static inline struct folio *'),('gup_put_folio','static void'),('try_grab_folio_fast','static struct folio *'),('gup_fast_folio_allowed','static bool'),('gup_fast_pte_range','static int'),('gup_fast_pmd_range','static int'),('gup_fast_pud_range','static int'),('gup_fast_p4d_range','static int'),('gup_fast_pgd_range','static void'),('gup_fast','static unsigned long'),('gup_fast_fallback','static int'),('is_valid_gup_args','static bool'),('get_user_pages_fast','int')]),
    ('mm/pgtable-generic.c',[('__pte_offset_map','pte_t *')]),
    ('arch/arm64/include/asm/pgtable.h',[('pud_pgtable','static inline pmd_t *'),('p4d_to_folded_pud','static inline pud_t *'),('pud_offset_lockless','static inline pud_t *'),('ptep_get','static inline pte_t'),('ptep_get_lockless','static inline pte_t')]),
    ('include/linux/pgtable.h',[('pte_offset_kernel','static inline pte_t *'),('pmd_offset','static inline pmd_t *'),('__pte_map','static inline pte_t *'),('pte_unmap','static inline void')]),
    ('mm/filemap.c',[('filemap_get_entry','void *'),('folio_unlock','void'),('generic_perform_write','ssize_t'),('find_get_entry','static inline struct folio *'),('find_lock_entries','unsigned'),('find_get_entries','unsigned')]),
    ('mm/truncate.c',[('truncate_cleanup_folio','static void'),('truncate_inode_folio','int'),('truncate_inode_partial_folio','bool')]),
    ('mm/util.c',[('folio_mapping','struct address_space *')]),
    ('include/linux/percpu-rwsem.h',[('percpu_down_read', 'static inline void'), ('percpu_down_read_trylock', 'static inline bool'), ('percpu_up_read', 'static inline void')]),
    ('include/linux/rcu_sync.h',[('rcu_sync_is_idle', 'static inline bool')]),
    ('kernel/sched/core.c',[('__cond_resched', 'int __sched')]),
    ('kernel/rcu/tree_plugin.h',[('rcu_all_qs', 'void')]),
    ('arch/arm64/include/asm/preempt.h',[('should_resched', 'static inline bool')]),
    ('include/linux/sched.h',[('_cond_resched', 'static inline int')]),
    ('include/linux/slab.h',[('kmalloc_type','static __always_inline enum kmalloc_cache_type'),('kmalloc_noprof','static __always_inline __alloc_size(1) void *'),('kmalloc_array_noprof','static inline __alloc_size(1, 2) void *'),('__kmalloc_index','static __always_inline unsigned int'),('kzalloc_noprof','static inline __alloc_size(1) void *')]),
    ('mm/slab.h',[('size_index_elem','static inline unsigned int'),('kmalloc_slab','static inline struct kmem_cache *'),('__slub_debug_enabled','static inline bool'),('kmem_cache_debug_flags','static inline bool'),('slab_want_init_on_alloc','static inline bool'),('slab_want_init_on_free','static inline bool')]),
    ('mm/slub.c',[('kmalloc_trace_noprof','void *'),('stat','static inline void'),('stat_add','static inline void'),('freelist_ptr_encode','static inline freeptr_t'),('freelist_ptr_decode','static inline void *'),('get_freepointer','static inline void *'),('prefetch_freepointer','static void'),('get_freepointer_safe','static inline void *'),('set_freepointer','static inline void'),('memcg_slab_post_alloc_hook','static __fastpath_inline bool'),('memcg_slab_free_hook','static __fastpath_inline void'),('slab_free_hook','static __always_inline bool'),('next_tid','static inline unsigned long'),('node_match','static inline int'),('__update_cpu_freelist_fast','static inline bool'),('__slab_alloc_node','static __always_inline void *'),('maybe_wipe_obj_freeptr','static __always_inline void'),('should_failslab','noinline int'),('slab_pre_alloc_hook','static __fastpath_inline struct kmem_cache *'),('slab_post_alloc_hook','static __fastpath_inline bool'),('slab_alloc_node','static __fastpath_inline void *'),('__do_kmalloc_node','static __always_inline void *'),('__kmalloc_noprof','void *'),('do_slab_free','static __always_inline void'),('slab_free','static __fastpath_inline void'),('kfree','void')]),
    ('kernel/locking/rwsem.c',[('down_write', 'void __sched'), ('up_write', 'void'), ('__down_write_common', 'static inline int'), ('__down_write', 'static inline void'), ('rwsem_write_trylock', 'static inline bool'), ('rwsem_set_owner', 'static inline void'), ('rwsem_clear_owner', 'static inline void'), ('__up_write', 'static inline void')]),
    ('include/linux/rwsem.h',[('rwsem_is_locked','static inline int')]),
    ('mm/backing-dev.c',[('inode_to_bdi','struct backing_dev_info *')]),
    ('mm/page-writeback.c',[('balance_dirty_pages_ratelimited_flags','int'),('balance_dirty_pages_ratelimited','void'),('noop_dirty_folio','bool'),('folio_mark_dirty','bool'),('folio_wait_writeback','void')]),
    ('arch/arm64/mm/flush.c',[('flush_dcache_folio','void'),('flush_dcache_page','void')]),
    ('mm/swap.c',[('folio_inc_refs','static void'),('folio_mark_accessed','void'),('folio_batch_remove_exceptionals','void')]),
    ('mm/shmem.c',[('shmem_mapping','bool'),('shmem_get_folio_gfp','static int'),('shmem_get_folio','int'),('shmem_file_read_iter','ssize_t'),('shmem_file_write_iter','ssize_t'),('shmem_write_begin','int'),('shmem_write_end','int'),('shmem_reacct_size','static inline int'),('shmem_recalc_inode','static void'),('shmem_get_partial_folio','static struct folio *'),('shmem_undo_range','static void'),('shmem_truncate_range','void'),('shmem_setattr','int')]),
    ('kernel/time/timekeeping.c',[('tk_xtime','static inline struct timespec64'),('ktime_get_coarse_real_ts64','void')]),
    ('kernel/user_namespace.c',[('cmp_map_id','static int'),('map_id_up_base','static struct uid_gid_extent *'),('map_id_up_max','static struct uid_gid_extent *'),('map_id_up','u32'),('from_kuid','uid_t'),('from_kuid_munged','uid_t'),('from_kgid','gid_t'),('from_kgid_munged','gid_t')]),
    ('fs/mnt_idmapping.c',[('initial_idmapping','static inline bool'),('make_vfsuid','vfsuid_t'),('make_vfsgid','vfsgid_t')]),
    ('fs/libfs.c',[('inode_maybe_inc_iversion','bool')]),
    ('fs/inode.c',[('timestamp_truncate','struct timespec64'),('current_time','struct timespec64'),('inode_set_ctime_current','struct timespec64'),('inode_update_timestamps','int'),('generic_update_time','int'),('inode_update_time','int'),('relatime_need_update','static bool'),('atime_needs_update','bool'),('touch_atime','void'),('inode_needs_update_time','static int'),('__file_update_time','static int'),('file_update_time','int'),('file_remove_privs_flags','int'),('file_remove_privs','int'),('dentry_needs_remove_privs','int')]),
    ('fs/attr.c',[('may_setattr','int'),('inode_newsize_ok','int'),('setattr_prepare','int'),('setattr_copy','void'),('notify_change','int')]),
    ('fs/namespace.c',[('__mnt_is_readonly', 'bool'), ('mnt_get_write_access_file', 'int'), ('mnt_put_write_access_file', 'void'), ('mnt_inc_writers', 'static inline void'), ('mnt_dec_writers', 'static inline void'), ('mnt_is_readonly', 'static int'), ('mnt_get_write_access', 'int'), ('mnt_put_write_access', 'void')]),
    ('fs/fs-writeback.c',[('__mark_inode_dirty','void')]),
    ('fs/locks.c',[('locks_remove_posix','void')]),
    ('security/security.c',[('security_file_permission','int'),('security_file_fcntl','int'),('security_inode_setattr','int'),('security_inode_post_setattr','void'),('security_file_truncate','int')]),
    ('include/linux/find.h',[('find_next_zero_bit','static inline unsigned long')]),
    ('lib/find_bit.c',[('_find_next_zero_bit','unsigned long')]),
    ('fs/notify/dnotify/dnotify.c',[('dnotify_flush','void')]),
    ('arch/arm64/include/asm/syscall.h',[('syscall_set_return_value','static inline void')]),
    ('arch/arm64/kernel/syscall.c',[('do_ni_syscall','static long'),('__invoke_syscall','static long'),('invoke_syscall','static void'),('has_syscall_work','static inline bool'),('el0_svc_common','static void'),('do_el0_svc','void')]),
    ('arch/arm64/kernel/entry-common.c',[('__enter_from_user_mode','static __always_inline void'),('enter_from_user_mode','static __always_inline void'),('__exit_to_user_mode','static __always_inline void'),('exit_to_user_mode_prepare','static __always_inline void'),('exit_to_user_mode','static __always_inline void'),('cortex_a76_erratum_1463225_svc_handler','static void'),('fp_user_discard','static inline void'),('el0_svc','static void noinstr'),('el0t_64_sync_handler','asmlinkage void noinstr')]),
]
# arm64 assembly the slice runs verbatim: memset.S and the exception entry,
# entry.S (vectors, kernel_entry/kernel_exit, ret_to_user). Both assemble against
# the kernel's own headers, pinned whole under upstream/kernel-tree (6.10.14, the
# running kernel), as Kbuild builds them: -D__ASSEMBLY__ -D__KERNEL__, kconfig.h
# and the live kernel's autoconf.h, with the generated headers made here:
# asm/cpucaps.h and asm/sysreg-defs.h by the kernel's own awk generators from the
# pinned arch/arm64/tools inputs, the generic asm/types.h and asm/errno.h
# wrappers, and asm/asm-offsets.h from the model's checked layout block.
# entry-glue.S is the reviewed model of the hardware around them: it enters
# EL0, takes a real SVC into Linux's vector and returns through kernel_exit.
# memset.S needs Normal memory: the fd-control port starts with the MMU on.
FD_CONTROL_KERNEL_TREE=(
    'arch/arm64/include/asm/alternative-macros.h',
    'arch/arm64/include/asm/alternative.h',
    'arch/arm64/include/asm/asm-bug.h',
    'arch/arm64/include/asm/asm-extable.h',
    'arch/arm64/include/asm/asm-uaccess.h',
    'arch/arm64/include/asm/asm_pointer_auth.h',
    'arch/arm64/include/asm/assembler.h',
    'arch/arm64/include/asm/boot.h',
    'arch/arm64/include/asm/brk-imm.h',
    'arch/arm64/include/asm/bug.h',
    'arch/arm64/include/asm/cache.h',
    'arch/arm64/include/asm/cpufeature.h',
    'arch/arm64/include/asm/cputype.h',
    'arch/arm64/include/asm/debug-monitors.h',
    'arch/arm64/include/asm/esr.h',
    'arch/arm64/include/asm/gpr-num.h',
    'arch/arm64/include/asm/hwcap.h',
    'arch/arm64/include/asm/insn-def.h',
    'arch/arm64/include/asm/insn.h',
    'arch/arm64/include/asm/irq.h',
    'arch/arm64/include/asm/kernel-pgtable.h',
    'arch/arm64/include/asm/linkage.h',
    'arch/arm64/include/asm/memory.h',
    'arch/arm64/include/asm/mmu.h',
    'arch/arm64/include/asm/page-def.h',
    'arch/arm64/include/asm/page.h',
    'arch/arm64/include/asm/pgtable-hwdef.h',
    'arch/arm64/include/asm/processor.h',
    'arch/arm64/include/asm/ptrace.h',
    'arch/arm64/include/asm/rwonce.h',
    'arch/arm64/include/asm/scs.h',
    'arch/arm64/include/asm/sparsemem.h',
    'arch/arm64/include/asm/sysreg.h',
    'arch/arm64/include/asm/thread_info.h',
    'arch/arm64/include/asm/unistd.h',
    'arch/arm64/include/uapi/asm/bitsperlong.h',
    'arch/arm64/include/uapi/asm/hwcap.h',
    'arch/arm64/include/uapi/asm/ptrace.h',
    'arch/arm64/include/uapi/asm/sve_context.h',
    'arch/arm64/include/uapi/asm/unistd.h',
    'arch/arm64/kernel/entry.S',
    'arch/arm64/lib/memset.S',
    'arch/arm64/tools/cpucaps',
    'arch/arm64/tools/gen-cpucaps.awk',
    'arch/arm64/tools/gen-sysreg.awk',
    'arch/arm64/tools/sysreg',
    'include/asm-generic/bitsperlong.h',
    'include/asm-generic/bug.h',
    'include/asm-generic/getorder.h',
    'include/asm-generic/int-ll64.h',
    'include/asm-generic/rwonce.h',
    'include/linux/args.h',
    'include/linux/arm-smccc.h',
    'include/linux/bits.h',
    'include/linux/build_bug.h',
    'include/linux/compiler.h',
    'include/linux/compiler_types.h',
    'include/linux/const.h',
    'include/linux/errno.h',
    'include/linux/export.h',
    'include/linux/init.h',
    'include/linux/instrumentation.h',
    'include/linux/kasan-tags.h',
    'include/linux/kconfig.h',
    'include/linux/linkage.h',
    'include/linux/once_lite.h',
    'include/linux/sizes.h',
    'include/linux/stringify.h',
    'include/linux/types.h',
    'include/uapi/asm-generic/bitsperlong.h',
    'include/uapi/asm-generic/errno-base.h',
    'include/uapi/asm-generic/errno.h',
    'include/uapi/asm-generic/int-ll64.h',
    'include/uapi/asm-generic/types.h',
    'include/uapi/asm-generic/unistd.h',
    'include/uapi/linux/bits.h',
    'include/uapi/linux/const.h',
    'include/uapi/linux/errno.h',
    'include/uapi/linux/types.h',
    'include/vdso/bits.h',
    'include/vdso/const.h',
)
FD_CONTROL_SOURCES+=[('kernel-tree/'+f,[]) for f in FD_CONTROL_KERNEL_TREE]
FD_CONTROL_ASSEMBLY={'linux-memset.S':'kernel-tree/arch/arm64/lib/memset.S','linux-entry.S':'kernel-tree/arch/arm64/kernel/entry.S'}
FD_CONTROL_KERNEL_INCLUDES=('linux-kernel/gen','linux-kernel/arch/arm64/include','linux-kernel/include','linux-kernel/arch/arm64/include/uapi','linux-kernel/include/uapi')
FD_CONTROL_ASSEMBLY_OPTIONS=dict(defines=['__ASSEMBLY__','__KERNEL__'],preincludes=['linux-kernel/include/linux/kconfig.h','linux-kernel/gen/generated/autoconf.h'],include_dirs=list(FD_CONTROL_KERNEL_INCLUDES))

def kernel_headers(root,sources,config):
    """The kernel include tree for the assembly, with the headers a kernel build generates."""
    tree=sources/'linux-kernel'
    for name in FD_CONTROL_KERNEL_TREE:
        (tree/name).parent.mkdir(parents=True,exist_ok=True);(tree/name).write_bytes((upstream(root/'native')/'kernel-tree'/name).read_bytes())
    gen=tree/'gen';(gen/'asm').mkdir(parents=True);(gen/'generated').mkdir()
    for header,script,data in (('cpucaps.h','gen-cpucaps.awk','cpucaps'),('sysreg-defs.h','gen-sysreg.awk','sysreg')):
        out=subprocess.run(['awk','-f',str(tree/'arch/arm64/tools'/script),str(tree/'arch/arm64/tools'/data)],capture_output=True,text=True,check=True).stdout
        (gen/'asm'/header).write_text(out)
    for name in ('types.h','errno.h'):(gen/'asm'/name).write_text('#include <asm-generic/%s>\n'%name)
    lines=['/* Generated from the live kernel configuration. */']
    for line in config.splitlines():
        m=re.fullmatch(r'(CONFIG_\w+)=(.*)',line.strip())
        if m:lines.append('#define %s %s'%(m.group(1)+'_MODULE' if m.group(2)=='m' else m.group(1),'1' if m.group(2) in ('y','m') else m.group(2)))
    (gen/'generated/autoconf.h').write_text('\n'.join(lines)+'\n')
    model=(sources/'model.h').read_text()
    block=model[model.index('/* ASM-OFFSETS BEGIN */'):model.index('/* ASM-OFFSETS END */')]
    (gen/'asm/asm-offsets.h').write_text('/* The model layout block of model.h (checked there by _Static_assert). */\n'+block+'/* ASM-OFFSETS END */\n')

# Calls through an operation table (f_op->read_iter) become direct calls to a
# reviewed dispatch model that selects the callee by the table's object class.
# Each listed call text occurs exactly once in its original body; nothing else changes.
FD_CONTROL_REWRITES={
    # arm64 __va (the linear map) at each level of GUP-fast's walk: the model for that level's pinned table page,
    # which returns that level's descriptor pointer (so the void * cast of __va's result goes too). pte_offset_kernel
    # reads pmd_page_vaddr(pmd), __va(pmd_page_paddr(pmd)) as an integer, back as a pointer: the model directly.
    'pud_offset_lockless':[('(pud_t *)__va(','osrec_pud_va(')],
    'pud_pgtable':[('(pmd_t *)__va(','osrec_pmd_va(')],
    'pte_offset_kernel':[('(pte_t *)pmd_page_vaddr(*pmd)','osrec_pte_va(pmd_page_paddr(*pmd))')],
    # The walk's store of each pinned page: its index (*nr) is bounded only by the trip count (end - start is one
    # page for get_futex_key's single page), which interval analysis cannot relate. The model asserts index 0.
    'gup_fast_pte_range':[('pages[*nr] = page;','osrec_gup_store(pages, *nr, page);')],
    'vfs_read':[('file->f_op->read(file, buf, count, pos)','osrec_f_op_read(file->f_op, file, buf, count, pos)')],
    'new_sync_read':[('filp->f_op->read_iter(&kiocb, &iter)','osrec_f_op_read_iter(filp->f_op, &kiocb, &iter)')],
    'vfs_write':[('file->f_op->write(file, buf, count, pos)','osrec_f_op_write(file->f_op, file, buf, count, pos)')],
    'new_sync_write':[('filp->f_op->write_iter(&kiocb, &iter)','osrec_f_op_write_iter(filp->f_op, &kiocb, &iter)')],
    'do_iter_readv_writev':[('filp->f_op->read_iter(&kiocb, iter)','osrec_f_op_read_iter(filp->f_op, &kiocb, iter)'),('filp->f_op->write_iter(&kiocb, iter)','osrec_f_op_write_iter(filp->f_op, &kiocb, iter)')],
    'do_loop_readv_writev':[('filp->f_op->read(filp,','osrec_f_op_read(filp->f_op, filp,'),('filp->f_op->write(filp,','osrec_f_op_write(filp->f_op, filp,')],
    'inode_update_time':[('inode->i_op->update_time(inode, flags)','osrec_i_op_update_time(inode->i_op, inode, flags)')],
    '__mark_inode_dirty':[('sb->s_op->dirty_inode(inode,','osrec_s_op_dirty_inode(sb->s_op, inode,')],
    'generic_perform_write':[('a_ops->write_begin(file,','osrec_a_ops_write_begin(a_ops, file,'),('a_ops->write_end(file,','osrec_a_ops_write_end(a_ops, file,')],
    'folio_mark_dirty':[('mapping->a_ops->dirty_folio(mapping, folio)','osrec_a_ops_dirty_folio(mapping->a_ops, mapping, folio)')],
    'notify_change':[('inode->i_op->setattr(idmap, dentry, attr)','osrec_i_op_setattr(inode->i_op, idmap, dentry, attr)')],
    # LOCK_CONTENDED(lock, try, op) is op(lock) without CONFIG_LOCK_STAT: expanded in place, since the
    # context transform cannot pass the context through a callee named as a macro argument.
    'down_write':[('LOCK_CONTENDED(sem, __down_write_trylock, __down_write);','__down_write(sem);')],
    # A queued waiter's wake callback (futex_wake_mark for every wait the slice admits).
    'futex_wake':[('this->wake(&wake_q, this)','osrec_futex_q_wake(this->wake, &wake_q, this)')],
    'futex_requeue':[('this->wake(&wake_q, this)','osrec_futex_q_wake(this->wake, &wake_q, this)')],
    'futex_wake_op':[('this->wake(&wake_q, this);\n\t\t\tif (++ret','osrec_futex_q_wake(this->wake, &wake_q, this);\n\t\t\tif (++ret'),
                     ('this->wake(&wake_q, this);\n\t\t\t\tif (++op_ret','osrec_futex_q_wake(this->wake, &wake_q, this);\n\t\t\t\tif (++op_ret')],
    # The always-inline iterators take their step as a constant: the two user-address
    # steps are named by an enumeration (model.h) and called directly where the
    # iterator calls its step.
    '_copy_to_iter':[('copy_to_user_iter, memcpy_to_iter','OSREC_USTEP_COPY_TO_USER, memcpy_to_iter')],
    '__copy_from_iter':[('copy_from_user_iter, memcpy_from_iter','OSREC_USTEP_COPY_FROM_USER, memcpy_from_iter')],
    'iterate_ubuf':[('step(base + iter->iov_offset, 0, len, priv, priv2)','(step == OSREC_USTEP_COPY_TO_USER ? copy_to_user_iter(base + iter->iov_offset, 0, len, priv, priv2) : copy_from_user_iter(base + iter->iov_offset, 0, len, priv, priv2))')],
    'iterate_iovec':[('step(p->iov_base + skip, progress, part, priv, priv2)','(step == OSREC_USTEP_COPY_TO_USER ? copy_to_user_iter(p->iov_base + skip, progress, part, priv, priv2) : copy_from_user_iter(p->iov_base + skip, progress, part, priv, priv2))')],
    'filp_flush':[('filp->f_op->flush(filp, id)','osrec_f_op_flush(filp->f_op, filp, id)')],
    'locks_remove_posix':[('lock.fl_ops->fl_release_private(&lock)','osrec_fl_release_private(lock.fl_ops, &lock)')],
    # The system call table holds syscall numbers, not function pointers (see model.h).
    '__invoke_syscall':[('syscall_fn(regs)','osrec_sys_call(syscall_fn, regs)')],
}

def rewrite_calls(found,rewrites):
    """Apply the reviewed operation-table call rewrites to extracted bodies."""
    for name,edits in rewrites.items():
        body=found[name]['body']
        for old,new in edits:
            if body.count(old.encode())!=1:raise ValueError('reviewed call rewrite does not match '+name)
            body=body.replace(old.encode(),new.encode())
        found[name]=dict(found[name],body=body,rewritten_calls=[old for old,_ in edits])
    return found

# The BPF LSM's default hooks: kernel/bpf/bpf_lsm.c defines one nop function per hook by expanding its
# LSM_HOOK macro over include/linux/lsm_hook_defs.h. The slice keeps the five hooks its LSM walks call.
BPF_LSM_HOOKS=('file_permission','file_fcntl','file_truncate','inode_setattr','inode_post_setattr')

def lsm_hook_definitions(macro,hooks,names):
    """Expand bpf_lsm.c's LSM_HOOK over the named lsm_hook_defs.h entries, as the preprocessor does.

    RET, DEFAULT and NAME take their arguments and __VA_ARGS__ the rest (whitespace collapsed); the
    result is `noinline RET bpf_lsm_NAME(ARGS) { return DEFAULT; }`.
    """
    if not re.search(rb'#define LSM_HOOK\(RET, DEFAULT, NAME, \.\.\.\)\t\\\nnoinline RET bpf_lsm_##NAME\(__VA_ARGS__\)\t\\\n\{\t*\\\n\treturn DEFAULT;\t*\\\n\}\n',macro):raise ValueError('reviewed LSM_HOOK definition differs')
    found={}
    for name in names:
        hits=list(re.finditer(rb'^LSM_HOOK\(([^,]+), ([^,]+), '+name.encode()+rb', ([^)]*)\)$',hooks,re.M))
        if len(hits)!=1:raise ValueError('missing/ambiguous LSM hook '+name)
        ret,default,args=(' '.join(g.decode().split()) for g in hits[0].groups())
        found['bpf_lsm_'+name]=dict(sha256=digest(hits[0].group(0)),signature=args,original=hits[0].group(0),body=('{\n\treturn %s;\n}'%default).encode(),syscall=False,
            declaration='noinline %s bpf_lsm_%s(%s)'%(ret,name,args),macro_expansion='kernel/bpf/bpf_lsm.c LSM_HOOK')
    return found

def definitions(source,profile='minimal',selected_roots=None,selected_helpers=None):
    """Extract only reviewed SYSCALL_DEFINE roots, retaining original body bytes."""
    found={}
    roots=dict(ROOTS)
    if profile in ('credentials','fsgid','group-setters','getgroups'):roots['setresgid']=3
    if profile in ('fsgid','group-setters','getgroups'):roots['setfsgid']=1
    if profile in ('group-setters','getgroups'):roots.update(setgid=1,setregid=2)
    if profile in ('fsuid','setresuid','uid-setters','credential-setters'):roots['setfsuid']=1
    if profile in ('setresuid','uid-setters','credential-setters'):roots['setresuid']=3
    if profile in ('uid-setters','credential-setters'):roots.update(setuid=1,setreuid=2)
    if profile=='credential-setters':roots.update(setgid=1,setregid=2,setresgid=3,setfsgid=1)
    if selected_roots is not None:roots=selected_roots
    for name,arity in roots.items():
        matches=list(re.finditer(rb'\bSYSCALL_DEFINE'+str(arity).encode()+rb'\(\s*'+name.encode()+rb'\b([^)]*)\)',source))
        if len(matches)!=1:raise ValueError('missing/ambiguous Linux syscall '+name)
        match=matches[0];parameters=match.group(1).decode('ascii').strip()
        parts=parameters[1:].split(',') if parameters.startswith(',') else []
        if len(parts)!=2*arity:raise ValueError('unsupported Linux syscall signature '+name)
        parameters=', '.join(parts[2*i].strip()+' '+parts[2*i+1].strip() for i in range(arity)) or 'void'
        start=match.end()
        while start<len(source) and source[start:start+1].isspace():start+=1
        if source[start:start+1]!=b'{':raise ValueError('Linux syscall body is missing '+name)
        depth=0;end=None
        for token in re.finditer(rb'/\*[\s\S]*?\*/|//[^\r\n]*|"(?:\\[\s\S]|[^"\\])*"|\'(?:\\[\s\S]|[^\'\\])*\'|[{}]',source[start:]):
            if token.group()==b'{':depth+=1
            elif token.group()==b'}':
                depth-=1
                if depth==0:end=start+token.end();break
        if end is None:raise ValueError('Linux syscall body is unbalanced '+name)
        original=source[match.start():end]
        found[name]=dict(sha256=digest(original),signature=parameters,original=original,body=source[start:end],syscall=True)
    helpers=['__sys_setresgid'] if profile in ('credentials','fsgid','group-setters','getgroups') else []
    if profile in ('fsgid','group-setters','getgroups'):helpers.append('__sys_setfsgid')
    if profile in ('group-setters','getgroups'):helpers+=['__sys_setgid','__sys_setregid']
    if profile in ('fsuid','setresuid','uid-setters','credential-setters'):helpers.append('__sys_setfsuid')
    if profile in ('setresuid','uid-setters','credential-setters'):helpers += ['__sys_setresuid']
    if profile in ('uid-setters','credential-setters'):helpers += ['__sys_setuid','__sys_setreuid']
    if profile=='credential-setters':helpers += ['__sys_setgid','__sys_setregid','__sys_setresgid','__sys_setfsgid']
    helpers=[(n,'long') for n in helpers] if selected_helpers is None else selected_helpers
    if profile in ('setresuid','uid-setters','credential-setters') and selected_helpers is None:helpers += [('set_user','static int'),('flag_nproc_exceeded','static void')]
    for name,returns in helpers:
        if returns not in ('static __always_inline __must_check bool','static inline __must_check unsigned long','static __always_inline unsigned long __must_check','static inline ktime_t','ktime_t','static __always_inline int','static inline freeptr_t','static inline void *','static void','static __fastpath_inline bool','static __fastpath_inline void','static __always_inline bool','static inline unsigned long','static __always_inline void *','static __always_inline void','noinline int','static __fastpath_inline struct kmem_cache *','static __fastpath_inline void *','void *','static __always_inline enum kmalloc_cache_type','static __always_inline __alloc_size(1) void *','static inline __alloc_size(1, 2) void *','static inline __alloc_size(1) void *','static inline unsigned int','static inline struct kmem_cache *','long','static long','static unsigned long','unsigned long','static inline struct fd','static void','static int','int','void','bool','static inline int','static inline unsigned','static kernel_cap_t','static inline void','static inline kernel_cap_t','static unsigned int','static struct file *','static inline struct file *','struct file *','static inline bool','loff_t','static off_t','static inline loff_t *','ssize_t','static ssize_t','static inline struct fsnotify_sb_info *','static inline struct inode *','static inline loff_t','static inline struct timespec64','static inline struct user_namespace *','static inline vfsuid_t','static inline vfsgid_t','static inline enum iter_type','static inline size_t','static inline u64','static inline struct mnt_idmap *','static inline uid_t','static inline gid_t','static inline void *','static inline unsigned long','static inline struct xa_node *','static inline gfp_t','static inline struct page *','static void *','static __always_inline void *','void *','size_t','static bool','struct timespec64','vfsuid_t','vfsgid_t','static inline struct dentry *','static inline const struct iovec *','struct address_space *','struct backing_dev_info *','static inline unsigned int','static inline unsigned','static inline pgoff_t','static inline struct folio *','unsigned','static struct folio *','static __always_inline void','static __always_inline unsigned long','static void noinstr','asmlinkage void noinstr','static struct uid_gid_extent *','u32','uid_t','gid_t','static inline struct file_lock_context *','static __always_inline size_t','static __always_inline __s64','static __always_inline __s32','static __always_inline unsigned int','pte_t *','static __noclone int','struct iovec *','static __always_inline bool','struct futex_hash_bucket *','struct futex_q *','struct hrtimer_sleeper *','static inline u32','static inline __u32','void __sched','static inline struct mount *','int __sched','static inline bool __must_check','static inline int','static inline pud_t *','static inline pmd_t *','static inline pte_t *','static inline pte_t'):raise ValueError('unsupported reviewed helper declaration')
        separator=rb'\s*' if returns.endswith('*') else rb'\s+'
        matches=list(re.finditer(rb'\b'+rb'\s+'.join(re.escape(t) for t in returns.encode().split())+separator+name.encode()+rb'\(([^)]*)\)((?:\s*__(?:releases|acquires)\([^)]*\))*)\s*(?=\{)',source))
        if len(matches)!=1:raise ValueError('missing/ambiguous Linux helper '+name)
        match=matches[0];start=match.end();depth=0;end=None
        for token in re.finditer(rb'/\*[\s\S]*?\*/|//[^\r\n]*|"(?:\\[\s\S]|[^"\\])*"|\'(?:\\[\s\S]|[^\'\\])*\'|[{}]',source[start:]):
            if token.group()==b'{':depth+=1
            elif token.group()==b'}':
                depth-=1
                if depth==0:end=start+token.end();break
        if end is None:raise ValueError('unbalanced Linux helper '+name)
        original=source[match.start():end]
        found[name]=dict(sha256=digest(original),signature=match.group(1).decode('ascii'),original=original,body=source[start:end],syscall=False,declaration=returns+' '+name+'('+match.group(1).decode('ascii')+')'+(' '+' '.join(match.group(2).decode('ascii').split()) if match.group(2) else ''))
    return found

def source_identity(root):
    root=Path(root);review=json.loads((root/'source-identity.json').read_text())
    profile=review.get('profile','minimal');source=(upstream(root)/'kernel/sys.c').read_bytes();found=definitions(source,selected_roots={**ROOTS,**({'setrlimit':2} if profile=='file-setrlimit' else {}),**({'getrlimit':2} if profile in ('file-rlimit','file-limits','file-setrlimit') else {}),**({'setuid':1,'setreuid':2,'setresuid':3} if profile in ('file-credentials','file-rlimit','file-limits','file-setrlimit') else {}),'setfsgid':1,**({'setgid':1,'setregid':2,'setresgid':3} if profile in ('file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else {}),**({'setfsuid':1} if profile in ('file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else {})},selected_helpers=([('do_prlimit','static int')] if profile=='file-setrlimit' else [])+([('__sys_setuid','long'),('__sys_setreuid','long'),('__sys_setresuid','long'),('set_user','static int'),('flag_nproc_exceeded','static void')] if profile in ('file-credentials','file-rlimit','file-limits','file-setrlimit') else [])+[('__sys_setfsgid','long')]+([(n,'long') for n in ('__sys_setgid','__sys_setregid','__sys_setresgid')] if profile in ('file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else [])+([('__sys_setfsuid','long')] if profile in ('file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else [])) if profile in ('file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else definitions(source,profile)
    extra=review.get('additional_sources',{})
    if profile in ('getgroups','setgroups','setgroups-denied','capabilities','capget','prctl','fsuid','setresuid','uid-setters','credential-setters'):
        expected_extra=({'kernel/cred.c'} if profile in ('setresuid','uid-setters','credential-setters') else set()) | ({'kernel/groups.c','kernel/capability.c','security/commoncap.c','include/linux/capability.h'} if profile in ('fsuid','setresuid','uid-setters','credential-setters') else {'kernel/groups.c','kernel/capability.c','security/commoncap.c'} if profile in ('capabilities','capget','prctl','fsuid','setresuid','uid-setters','credential-setters') else {'kernel/groups.c'})
        if set(extra)!=expected_extra:raise ValueError('Linux supplementary-group source list differs')
        data=(upstream(root)/'kernel/groups.c').read_bytes()
        if digest(data)!=extra['kernel/groups.c']:raise ValueError('Linux supplementary-group source identity mismatch')
        roots={'getgroups':2};helpers=[('groups_to_user','static int')]
        if profile in ('setgroups','setgroups-denied','capabilities','capget','prctl','fsuid','setresuid','uid-setters','credential-setters'):roots['setgroups']=2;helpers += [('groups_from_user','static int'),('set_groups','void'),('set_current_groups','int'),('may_setgroups','bool')]
        found.update(definitions(data,profile,selected_roots=roots,selected_helpers=helpers))
        if profile in ('capabilities','capget','prctl','fsuid','setresuid','uid-setters','credential-setters'):
            cap_roots={'capset':2};cap_helpers=[('cap_validate_magic','static int'),('mk_kernel_cap','static kernel_cap_t')];security_helpers=[('cap_inh_is_capped','static inline int'),('cap_capset','int')]
            if profile in ('capget','prctl','fsuid','setresuid','uid-setters','credential-setters'):cap_roots['capget']=2;cap_helpers.append(('cap_get_target_pid','static inline int'));security_helpers.append(('cap_capget','int'))
            if profile in ('prctl','fsuid','setresuid','uid-setters','credential-setters'):security_helpers += [('cap_prctl_drop','static int'),('cap_task_prctl','int')]
            if profile in ('fsuid','setresuid','uid-setters','credential-setters'):
                data=(upstream(root)/'include/linux/capability.h').read_bytes()
                if digest(data)!=extra['include/linux/capability.h']:raise ValueError('Linux filesystem-capability source identity mismatch')
                found.update(definitions(data,profile,selected_roots={},selected_helpers=[('cap_drop','static inline kernel_cap_t'),('cap_drop_fs_set','static inline kernel_cap_t'),('cap_raise_fs_set','static inline kernel_cap_t')]))
                security_helpers += [('cap_emulate_setxuid','static inline void'),('cap_task_fix_setuid','int')]
            for filename,roots,helpers in [('kernel/capability.c',cap_roots,cap_helpers),('security/commoncap.c',{},security_helpers)]:
                data=(upstream(root)/filename).read_bytes()
                if digest(data)!=extra[filename]:raise ValueError('Linux capability source identity mismatch')
                found.update(definitions(data,profile,selected_roots=roots,selected_helpers=helpers))
    elif profile in ('fd-dup','file-io','file-positioned','fd-control','close-range','fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):
        if set(extra)!=({'kernel/cred.c'} if profile in ('file-credentials','file-rlimit','file-limits','file-setrlimit') else set()) | ({'include/uapi/asm-generic/fcntl.h'} if profile in ('file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else set()) | ({'kernel/groups.c'} if profile in ('file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else set()) | ({'include/linux/capability.h'} if profile in ('file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else set()) | ({'kernel/capability.c','security/commoncap.c'} if profile in ('file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else set()) | ({'fs/stat.c','include/uapi/asm-generic/stat.h'} if profile in ('fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else set()) | ({'fs/file.c','fs/open.c','fs/read_write.c'} if profile in ('file-io','file-positioned','fd-control','close-range','fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else {'fs/file.c','fs/open.c'}) | ({'fs/fcntl.c','kernel/futex/syscalls.c','kernel/bpf/bpf_lsm.c','include/linux/lsm_hook_defs.h',*(f for f,_ in FD_CONTROL_SOURCES)} if profile=='fd-control' else set()) | ({'kernel/futex/syscalls.c','kernel/futex/futex.h'} if profile=='file-setrlimit' else set()):raise ValueError('Linux descriptor source list differs')
        for filename,roots,helpers in [('fs/file.c',{'dup':1,'dup3':3},FD_HELPERS+([('__fget_light','static unsigned long'),('__fdget','unsigned long'),('__fdget_raw','unsigned long'),('file_needs_f_pos_lock','static inline bool'),('__fdget_pos','unsigned long'),('__f_unlock_pos','void'),('expand_files','static int')] if profile=='fd-control' else [])+([('f_dupfd','int'),('set_close_on_exec','void'),('get_close_on_exec','bool')] if profile in ('fd-control','close-range','fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else [])+([('last_fd','static inline unsigned'),('__range_cloexec','static inline void'),('__range_close','static inline void'),('__close_range','int')] if profile in ('close-range','fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else [])),('fs/open.c',{'close':1,**({'fchown':3} if profile in ('fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else {}),**({'fchmod':2} if profile in ('fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else {}),**({'close_range':3} if profile in ('close-range','fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else {}),**({'ftruncate':2} if profile in ('file-positioned','fd-control','close-range','fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else {})},[('filp_close','int')]+([('filp_flush','static int'),('do_truncate','int')] if profile=='fd-control' else [])+([('setattr_vfsuid','static inline bool'),('setattr_vfsgid','static inline bool'),('chown_common','int'),('vfs_fchown','int'),('ksys_fchown','int')] if profile in ('fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else [])+([('vfs_fchmod','int'),('chmod_common','int')] if profile in ('fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else [])+([('do_ftruncate','long'),('do_sys_ftruncate','long')] if profile in ('file-positioned','fd-control','close-range','fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else []))]:
            data=(upstream(root)/filename).read_bytes()
            if digest(data)!=extra[filename]:raise ValueError('Linux descriptor source identity mismatch')
            found.update(definitions(data,profile,selected_roots=roots,selected_helpers=helpers))
        if profile in ('file-io','file-positioned','fd-control','close-range','fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):
            data=(upstream(root)/'fs/read_write.c').read_bytes()
            if digest(data)!=extra['fs/read_write.c']:raise ValueError('Linux file-I/O source identity mismatch')
            found.update(definitions(data,selected_roots={'read':3,'write':3,'lseek':3,**({'writev':3} if profile in ('fd-control','file-setrlimit') else {}),**({'pread64':4,'pwrite64':4} if profile in ('file-positioned','fd-control','close-range','fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else {})},selected_helpers=IO_HELPERS+([('new_sync_read','static ssize_t'),('vfs_read','ssize_t'),('new_sync_write','static ssize_t'),('vfs_write','ssize_t'),('generic_write_check_limits','int'),('generic_write_checks_count','int'),('generic_write_checks','ssize_t'),('do_iter_readv_writev','static ssize_t'),('do_loop_readv_writev','static ssize_t'),('vfs_writev','static ssize_t'),('do_writev','static ssize_t')] if profile=='fd-control' else [('do_writev','static ssize_t')] if profile=='file-setrlimit' else [])+([('ksys_pread64','ssize_t'),('ksys_pwrite64','ssize_t')] if profile in ('file-positioned','fd-control','close-range','fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else [])))
        if profile=='file-setrlimit':
            # The futex system call and do_futex are original; the wait/wake bodies below them are reviewed models.
            data=(upstream(root)/'kernel/futex/syscalls.c').read_bytes()
            if digest(data)!=extra['kernel/futex/syscalls.c']:raise ValueError('Linux futex source identity mismatch')
            found.update(definitions(data,selected_roots={'futex':6},selected_helpers=[('futex_cmd_has_timeout','static __always_inline bool'),('do_futex','long')]))
            data=(upstream(root)/'kernel/futex/futex.h').read_bytes()
            if digest(data)!=extra['kernel/futex/futex.h']:raise ValueError('Linux futex source identity mismatch')
            found.update(definitions(data,selected_roots={},selected_helpers=[('futex_to_flags','static inline unsigned int'),('should_fail_futex','static inline bool')]))
        if profile=='fd-control':
            data=(upstream(root)/'fs/fcntl.c').read_bytes()
            if digest(data)!=extra['fs/fcntl.c']:raise ValueError('Linux fcntl source identity mismatch')
            found.update(definitions(data,selected_roots={'fcntl':3},selected_helpers=[('do_fcntl','static long'),('check_fcntl_cmd','static int')]))
            macro=(upstream(root)/'kernel/bpf/bpf_lsm.c').read_bytes();hooks=(upstream(root)/'include/linux/lsm_hook_defs.h').read_bytes()
            if digest(macro)!=extra['kernel/bpf/bpf_lsm.c'] or digest(hooks)!=extra['include/linux/lsm_hook_defs.h']:raise ValueError('Linux BPF LSM hook source identity mismatch')
            found.update(lsm_hook_definitions(macro,hooks,BPF_LSM_HOOKS))
            data=(upstream(root)/'kernel/futex/syscalls.c').read_bytes()
            if digest(data)!=extra['kernel/futex/syscalls.c']:raise ValueError('Linux futex source identity mismatch')
            found.update(definitions(data,selected_roots={'futex':6},selected_helpers=[('futex_cmd_has_timeout','static __always_inline bool'),('futex_init_timeout','static __always_inline int'),('do_futex','long')]))
            for filename,helpers in FD_CONTROL_SOURCES:
                data=(upstream(root)/filename).read_bytes()
                if digest(data)!=extra[filename]:raise ValueError('Linux descriptor lookup source identity mismatch')
                found.update(definitions(data,selected_roots={},selected_helpers=helpers))
            rewrite_calls(found,FD_CONTROL_REWRITES)
        if profile in ('fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):
            for filename in ('fs/stat.c','include/uapi/asm-generic/stat.h'):
                if digest((upstream(root)/filename).read_bytes())!=extra[filename]:raise ValueError('Linux stat source/ABI identity mismatch')
            found.update(definitions((upstream(root)/'fs/stat.c').read_bytes(),selected_roots={'newfstat':2},selected_helpers=[('vfs_fstat','int'),('vfs_getattr','int'),('cp_new_stat','static int')]))
    elif extra:raise ValueError('unexpected Linux additional source')
    if profile in ('file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):
        for filename,roots,helpers in [('kernel/capability.c',{'capset':2,**({'capget':2} if profile in ('file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else {})},[('cap_validate_magic','static int'),('mk_kernel_cap','static kernel_cap_t')]+([('cap_get_target_pid','static inline int')] if profile in ('file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else [])),('security/commoncap.c',{},[('cap_inh_is_capped','static inline int'),('cap_capset','int')]+([('cap_capget','int')] if profile in ('file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else [])+([('cap_prctl_drop','static int'),('cap_task_prctl','int')] if profile in ('file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else [])+([('cap_emulate_setxuid','static inline void'),('cap_task_fix_setuid','int')] if profile in ('file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else []))]:
            data=(upstream(root)/filename).read_bytes()
            if digest(data)!=extra[filename]:raise ValueError('Linux file capability source identity mismatch')
            found.update(definitions(data,selected_roots=roots,selected_helpers=helpers))

    if profile in ('file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):
        data=(upstream(root)/'include/linux/capability.h').read_bytes()
        if digest(data)!=extra['include/linux/capability.h']:raise ValueError('Linux file FSUID capability source identity mismatch')
        found.update(definitions(data,selected_roots={},selected_helpers=[('cap_drop','static inline kernel_cap_t'),('cap_drop_fs_set','static inline kernel_cap_t'),('cap_raise_fs_set','static inline kernel_cap_t')]))
    if profile in ('file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):
        data=(upstream(root)/'kernel/groups.c').read_bytes()
        if digest(data)!=extra['kernel/groups.c']:raise ValueError('Linux file supplementary-group source identity mismatch')
        found.update(definitions(data,selected_roots={'getgroups':2,'setgroups':2},selected_helpers=[('groups_to_user','static int'),('groups_from_user','static int'),('set_groups','void'),('set_current_groups','int'),('may_setgroups','bool')]))
    if profile in ('setresuid','uid-setters','credential-setters','file-credentials','file-rlimit','file-limits','file-setrlimit'):
        data=(upstream(root)/'kernel/cred.c').read_bytes()
        if digest(data)!=extra['kernel/cred.c']:raise ValueError('Linux user-accounting source identity mismatch')
        found.update(definitions(data,profile,selected_roots={},selected_helpers=[('set_cred_ucounts','int')]))
    if digest(source)!=review['excerpt_sha256'] or {n:v['sha256'] for n,v in found.items()}!=review['definitions']:raise ValueError('Linux reviewed source identity mismatch')
    abi=(upstream(root)/'include/uapi/asm-generic/unistd.h').read_bytes()
    if digest(abi)!=review['syscall_abi_sha256']:raise ValueError('Linux syscall ABI source identity mismatch')
    numbers={n.decode():int(v) for n,v in re.findall(rb'^#define __NR_(\w+) (\d+)$',abi,re.M)}
    if {n:numbers[n] for n in ROOTS}!={'getpid':172,'gettid':178,'getppid':173,'getuid':174,'geteuid':175,'getgid':176,'getegid':177,'getresuid':148,'getresgid':150,'umask':166}:raise ValueError('Linux syscall ABI numbers differ')
    if profile in ('credentials','fsgid','group-setters','getgroups') and (numbers.get('setresgid')!=149 or numbers.get('setfsgid')!=152):raise ValueError('Linux credential syscall ABI differs')
    if profile in ('group-setters','getgroups') and (numbers.get('setgid')!=144 or numbers.get('setregid')!=143):raise ValueError('Linux group setter ABI differs')
    if profile in ('getgroups','setgroups','setgroups-denied','capabilities','capget','prctl','fsuid','setresuid','uid-setters','credential-setters') and {n:numbers.get(n) for n in ('getgroups','setgroups','mprotect')}!={'getgroups':158,'setgroups':159,'mprotect':226}:raise ValueError('Linux supplementary-group syscall ABI differs')
    if profile in ('setgroups-denied','capabilities','capget','prctl','fsuid','setresuid','uid-setters','credential-setters'):
        capability=(upstream(root)/'include/uapi/linux/capability.h').read_bytes()
        if digest(capability)!=review['capability_abi_sha256'] or numbers.get('capget')!=90:raise ValueError('Linux capability observation ABI differs')
    if profile in ('capabilities','capget','prctl','fsuid','setresuid','uid-setters','credential-setters') and (numbers.get('capset')!=91 or numbers.get('prctl')!=167):raise ValueError('Linux capability mutation ABI differs')
    if profile in ('prctl','fsuid','setresuid','uid-setters','credential-setters'):
        for name in ('prctl','securebits'):
            if digest((upstream(root)/('include/uapi/linux/'+name+'.h')).read_bytes())!=review[name+'_abi_sha256']:raise ValueError('Linux prctl ABI identity differs')
        if digest((upstream(root)/'kernel/prctl-dispatch-prefix.txt').read_bytes())!=review['prctl_dispatch_prefix_sha256']:raise ValueError('Linux prctl dispatch evidence differs')
    if profile in ('fsuid','setresuid','uid-setters','credential-setters') and numbers.get('setfsuid')!=151:raise ValueError('Linux filesystem-user syscall ABI differs')
    if profile in ('setresuid','uid-setters','credential-setters') and {n:numbers.get(n) for n in ('setresuid','getrlimit','prlimit64')}!={'setresuid':147,'getrlimit':163,'prlimit64':261}:raise ValueError('Linux saved-user/accounting syscall ABI differs')
    if profile in ('uid-setters','credential-setters') and {n:numbers.get(n) for n in ('setuid','setreuid')}!={'setuid':146,'setreuid':145}:raise ValueError('Linux user-setter syscall ABI differs')
    if profile=='credential-setters' and {n:numbers.get(n) for n in ('setgid','setregid','setresgid','setfsgid')}!={'setgid':144,'setregid':143,'setresgid':149,'setfsgid':152}:raise ValueError('Linux combined group-setter ABI differs')
    if profile in ('fd-dup','file-io','file-positioned','fd-control','close-range','fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):
        fd_numbers={n:int(v) for n,v in re.findall(rb'^#define (__NR(?:3264)?_\w+) (\d+)$',abi,re.M)}
        if {n:fd_numbers.get(n.encode()) for n in ('__NR_dup','__NR_dup3','__NR3264_fcntl','__NR_openat','__NR_close','__NR_getrlimit','__NR_prlimit64')}!={'__NR_dup':23,'__NR_dup3':24,'__NR3264_fcntl':25,'__NR_openat':56,'__NR_close':57,'__NR_getrlimit':163,'__NR_prlimit64':261}:raise ValueError('Linux descriptor syscall ABI differs')
    if profile in ('file-io','file-positioned','fd-control','close-range','fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') and {n:numbers.get(n) for n in ('lseek','read','write','pread64','memfd_create','mprotect')}!={'lseek':62,'read':63,'write':64,'pread64':67,'memfd_create':279,'mprotect':226}:raise ValueError('Linux file-I/O syscall ABI differs')
    if profile in ('file-positioned','fd-control','close-range','fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') and (numbers.get('pwrite64')!=68 or re.findall(rb'^#define __NR3264_ftruncate (\d+)$',abi,re.M)!=[b'46']):raise ValueError('Linux positioned/truncate syscall ABI differs')
    if profile in ('close-range','fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') and numbers.get('close_range')!=436:raise ValueError('Linux close_range syscall ABI differs')
    if profile in ('fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') and re.findall(rb'^#define __NR3264_fstat (\d+)$',abi,re.M)!=[b'80']:raise ValueError('Linux fstat syscall ABI differs')
    if profile in ('fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') and {n:numbers.get(n) for n in ('fchmod','fchown')}!={'fchmod':52,'fchown':55}:raise ValueError('Linux fchmod syscall ABI differs')
    if profile in ('fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') and {n:numbers.get(n) for n in ('capget','getgroups','setgroups')}!={'capget':90,'getgroups':158,'setgroups':159}:raise ValueError('Linux ownership observation ABI differs')
    if profile in ('fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') and numbers.get('capset')!=91:raise ValueError('Linux privileged ownership constructor ABI differs')
    if profile in ('file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') and (numbers.get('prctl')!=167 or digest((upstream(root)/'include/uapi/linux/capability.h').read_bytes())!=review['capability_abi_sha256']):raise ValueError('Linux file capability ABI differs')
    if profile in ('file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') and numbers.get('setfsgid')!=152:raise ValueError('Linux file fsgid ABI differs')
    if profile in ('file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') and (numbers.get('setfsuid')!=151 or digest((upstream(root)/'include/uapi/linux/securebits.h').read_bytes())!=review['securebits_abi_sha256']):raise ValueError('Linux file FSUID ABI differs')
    if profile in ('file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') and {n:numbers.get(n) for n in ('setgid','setregid','setresgid')}!={'setgid':144,'setregid':143,'setresgid':149}:raise ValueError('Linux combined scalar GID ABI differs')
    if profile in ('file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):
        flags=(upstream(root)/'include/uapi/asm-generic/fcntl.h').read_bytes()
        if digest(flags)!=extra['include/uapi/asm-generic/fcntl.h'] or re.findall(rb'^#define F_SETFL (\d+)$',flags,re.M)!=[b'4']:raise ValueError('Linux file-status ABI identity differs')
    if profile in ('file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):
        if digest((upstream(root)/'include/uapi/linux/prctl.h').read_bytes())!=review['prctl_abi_sha256'] or digest((upstream(root)/'kernel/prctl-dispatch-prefix.txt').read_bytes())!=review['prctl_dispatch_prefix_sha256']:raise ValueError('Linux file prctl ABI/dispatch identity differs')
    if profile in ('file-credentials','file-rlimit','file-limits','file-setrlimit') and {n:numbers.get(n) for n in ('setuid','setreuid','setresuid','getrlimit','prlimit64')}!={'setuid':146,'setreuid':145,'setresuid':147,'getrlimit':163,'prlimit64':261}:raise ValueError('Linux combined UID/accounting syscall ABI differs')
    if profile in ('file-rlimit','file-limits','file-setrlimit') and numbers.get('getrlimit')!=163:raise ValueError('Linux limit-query syscall ABI differs')
    if profile=='file-setrlimit' and numbers.get('setrlimit')!=164:raise ValueError('Linux limit-update syscall ABI differs')
    return review,found

def validate_capture(root):
    root=Path(root);raw=(root/'capture.json').read_bytes();capture=json.loads(raw);manifest=json.loads((root/'capture.manifest.json').read_text())
    if capture.get('format')!='osrec-linux-aarch64-capture-v1' or manifest.get('format')!='osrec-linux-aarch64-capture-manifest-v1':raise ValueError('invalid native Linux capture format')
    if manifest.get('native_linux_boot') is not True or manifest.get('semihosting') is not False or manifest.get('qemu_exit_status')!=0:raise ValueError('capture lacks a completed native Linux boot')
    identity=manifest['identity']
    if identity.get('architecture')!='aarch64':raise ValueError('native capture is not AArch64')
    if (manifest.get('root_kind','disk'),manifest.get('root_file','root.ext2')) not in (('disk','root.ext2'),('initramfs','root.cpio')):raise ValueError('unsupported native capture root')
    for filename,expected in (('capture.json',manifest['capture_sha256']),('init',manifest['init_sha256']),(manifest.get('root_file','root.ext2'),manifest['root_disk_sha256']),('qemu.log',manifest['qemu_log_sha256']),('kernel.config',identity['kernel_config_sha256'])):
        if digest((root/filename).read_bytes())!=expected:raise ValueError('Linux capture artifact identity mismatch: '+filename)
    for name,expected in manifest['source_sha256'].items():
        if '/' in name or '\\' in name or name in ('.','..') or digest((root/'sources'/name).read_bytes())!=expected:raise ValueError('Linux native source identity mismatch')
    review,_=source_identity(root)
    if manifest['reviewed_source_identity']!=review:raise ValueError('Linux capture/source binding differs')
    log=(root/'qemu.log').read_text(encoding='utf-8',errors='replace')
    matches=re.findall(r'^OSREC_LINUX_CAPTURE (\{[^\r\n]+\})$',log,re.M)
    if len(matches)!=1 or json.loads(matches[0])!={k:v for k,v in capture.items() if k!='format'} or 'OSREC_LINUX_CAPTURE_DONE' not in log or 'Linux version '+identity['kernel_release'] not in log:raise ValueError('Linux capture differs from native guest observations')
    initial=capture['initial'];ints=[initial[n] for n in ('pid','tgid','ppid','umask')]+initial['uids']+initial['gids']
    if len(initial['uids'])!=3 or len(initial['gids'])!=3 or any(type(v) is not int or not 0<=v<1<<32 for v in ints) or not 0<initial['pid']<=0x7fffffff or initial['tgid']!=initial['pid'] or initial['ppid']>0x7fffffff or initial['umask']>0o777:raise ValueError('Linux entry-state projection is invalid')
    profile=profile_for(capture)
    if profile!=review.get('profile','minimal'):raise ValueError('Linux capture/source profile differs')
    if profile in ('setresuid','uid-setters','credential-setters','file-credentials','file-rlimit','file-limits','file-setrlimit') and initial.get('nproc_limit')!=[UNCHANGED,UNCHANGED]:raise ValueError('Linux user-accounting NPROC limit differs')
    if profile in ('getgroups','setgroups','setgroups-denied','capabilities','capget','prctl','fsuid','setresuid','uid-setters','credential-setters') and (initial.get('groups')!=[4001,4003,4007]):raise ValueError('Linux supplementary-group entry state differs')
    if profile in ('setgroups','capabilities','capget','prctl','fsuid','setresuid','uid-setters','credential-setters') and (initial['uids']!=[1001,0,0] or initial['gids']!=[2001,2002,2003]):raise ValueError('Linux setgroups privileged entry state differs')
    if profile=='setgroups-denied' and (initial['uids']!=[1001,1002,0] or initial['gids']!=[2001,2002,2003] or type(initial.get('cap_setgid')) is not int or initial['cap_setgid']!=0):raise ValueError('Linux setgroups denied entry state differs')
    if profile in ('capabilities','capget') and (initial.get('capabilities')!=[4194368,4194368,0,(1<<41)-1,0] or any(type(v) is not int for v in initial['capabilities'])):raise ValueError('Linux initial capability sets differ')
    if profile=='prctl' and (initial.get('capabilities')!=[4194624,4194624,0,(1<<41)-1,0] or initial.get('securebits')!=0 or type(initial['securebits']) is not int or any(type(v) is not int for v in initial['capabilities'])):raise ValueError('Linux prctl entry state differs')
    if profile in ('fsuid','setresuid','uid-setters','credential-setters') and (initial.get('capabilities')!=[FS_INITIAL,FS_INITIAL,0,(1<<41)-1,0] or initial.get('securebits')!=0 or initial.get('fsuid')!=0 or type(initial['securebits']) is not int or type(initial['fsuid']) is not int or any(type(v) is not int for v in initial['capabilities'])):raise ValueError('Linux filesystem-user entry state differs')
    if profile=='fd-dup' and (initial.get('nofile_limit')!=[8,8] or initial.get('file_flags')!=[2,0x20000] or initial.get('fds')!=[[1,0],[1,0],[1,0],[2,1],[0,0],[0,0],[0,0],[0,0]]):raise ValueError('Linux descriptor entry state differs')
    if profile in ('file-io','file-positioned','fd-control','close-range','fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') and (initial.get('nofile_limit')!=[8,8] or initial.get('file_flags')!=[2,0x20002] or initial.get('fds')!=[[1,0],[1,0],[1,0],[2,1],[0,0],[0,0],[0,0],[0,0]] or initial.get('file')!=dict(size=16,pos=0,bytes=list(range(97,113))+[0]*48,**(dict(blocks=8) if profile in ('fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else {}),**(dict(mode=0o100777) if profile in ('fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else {}),**(dict(uid=1002,gid=0) if profile in ('fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else {}))):raise ValueError('Linux file-I/O entry state differs')
    if profile in ('fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') and (initial['uids']!=[1001,1002,0] or stat_metadata(initial)[1]['uid']!=1002 or stat_metadata(initial)[1]['mode']!=0o100777 or stat_metadata(initial)[0]['uid']==1002):raise ValueError('Linux chmod owner construction differs')
    if profile in ('fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') and (initial.get('owner_groups')!=[0] or any(type(v) is not int for v in initial['owner_groups']) or type(initial.get('ownership_effective_caps')) is not int or initial['ownership_effective_caps']!=(1 if profile in ('fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else 0) or stat_metadata(initial)[1]['gid']!=0):raise ValueError('Linux ownership authorization entry state differs')
    if profile in ('file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') and (initial.get('file_capabilities')!=[1,FILE_CAP_INITIAL|(64 if profile in ('file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else 0)|(256 if profile in ('file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else 0)|(128 if profile in ('file-credentials','file-rlimit','file-limits','file-setrlimit') else 0),0,(1<<41)-1,0] or any(type(v) is not int for v in initial['file_capabilities'])):raise ValueError('Linux file capability entry state differs')
    if profile in ('file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') and (type(initial.get('file_fsgid')) is not int or initial['file_fsgid']!=initial['gids'][1]):raise ValueError('Linux file filesystem-group entry state differs')
    if profile in ('file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') and (type(initial.get('file_fsuid')) is not int or initial['file_fsuid']!=initial['uids'][1] or type(initial.get('file_securebits')) is not int or initial['file_securebits']!=0):raise ValueError('Linux file filesystem-user entry state differs')
    if profile in ('file-limits','file-setrlimit'):
        limits=initial.get('rlimits')
        if (not isinstance(limits,list) or len(limits)!=16 or
            any(not isinstance(pair,list) or len(pair)!=2 or any(type(v) is not int or not 0<=v<=UNCHANGED for v in pair) or pair[0]>pair[1] for pair in limits) or
            limits[6]!=initial['nproc_limit'] or limits[7]!=initial['nofile_limit']):raise ValueError('Linux resource-limit entry state is invalid')
    expected,_=projection(capture)
    if capture['calls']!=expected:raise ValueError('native Linux return/memory/state transitions differ')
    return capture,manifest

def capture_sources(root,sources,capture):
    initial=capture['initial'];constants={**{n:initial[n] for n in ('pid','tgid','ppid','umask')},**{n:initial['uids'][i] for i,n in enumerate(('uid','euid','suid'))},**{n:initial['gids'][i] for i,n in enumerate(('gid','egid','sgid'))}}
    if profile_for(capture) in ('getgroups','setgroups','setgroups-denied','capabilities','capget','prctl','fsuid','setresuid','uid-setters','credential-setters'):constants.update(ngroups=len(initial['groups']),**{'group_'+str(i):v for i,v in enumerate(initial['groups']+[0]*(4-len(initial['groups'])))})
    if profile_for(capture)=='setgroups-denied':constants['cap_setgid']=initial['cap_setgid']
    if profile_for(capture) in ('capabilities','capget','prctl','fsuid','setresuid','uid-setters','credential-setters'):constants.update({'cap_'+name:initial['capabilities'][i] for i,name in enumerate(('effective','permitted','inheritable','bset','ambient'))})
    if profile_for(capture) in ('prctl','fsuid','setresuid','uid-setters','credential-setters'):constants['securebits']=initial['securebits']
    if profile_for(capture) in ('fsuid','setresuid','uid-setters','credential-setters'):constants['fsuid']=initial['fsuid']
    if profile_for(capture) in ('fd-dup','file-io','file-positioned','fd-control','close-range','fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):constants.update({'file_flags_'+str(i):v for i,v in enumerate(initial['file_flags'])})
    if profile_for(capture) in ('fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):
        for i,m in enumerate(stat_metadata(initial)):
            constants.update({'stat_'+n+'_'+str(i):v for n,v in m.items() if n!='bytes'})
    if profile_for(capture) in ('fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):constants['owner_group']=initial['owner_groups'][0]
    if profile_for(capture) in ('fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):constants['ownership_effective_caps']=initial['ownership_effective_caps']
    if profile_for(capture) in ('file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):constants.update({'file_cap_'+n:initial['file_capabilities'][i] for i,n in enumerate(('effective','permitted','inheritable','bset','ambient'))})
    if profile_for(capture) in ('file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):constants['file_fsgid']=initial['file_fsgid']
    if profile_for(capture) in ('file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):constants.update(file_fsuid=initial['file_fsuid'],file_securebits=initial['file_securebits'])
    if profile_for(capture) in ('file-limits','file-setrlimit'):constants.update({'rlimit_'+str(i)+'_'+name:value for i,pair in enumerate(initial['rlimits']) for name,value in zip(('cur','max'),pair)})
    count=len(capture['calls']);header='#ifndef OSREC_LINUX_CAPTURE_H\n#define OSREC_LINUX_CAPTURE_H\n#include <stdint.h>\n#define LINUX_CALLS '+str(count)+'\n'
    header+=''.join('#define LINUX_INITIAL_'+n.upper()+' '+str(v)+'u\n' for n,v in constants.items())
    header+='struct linux_observation {uint64_t number,args[3],raw;uint32_t words[8],umask_after;};\nextern const struct linux_observation linux_calls[LINUX_CALLS];\nextern const uint32_t linux_masks[LINUX_CALLS+1];\n#endif\n'
    if profile_for(capture) in ('prctl','fsuid','setresuid','uid-setters','credential-setters'):header=header.replace('args[3]','args[5]')
    if profile_for(capture) in ('file-positioned','fd-control','close-range','fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):header=header.replace('args[3]','args[4]')
    if profile_for(capture) in ('file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):header=header.replace('args[4]','args[5]')
    (sources/'capture.h').write_text(header)
    integer=lambda v:'UINT64_C('+str(v)+')'
    rows=['{'+integer(c['number'])+',{'+','.join(integer(v) for v in c['args'])+'},'+integer(c['raw_bits'])+',{'+','.join(str(v)+'u' for v in c['words'])+'},'+str(c['umask_after'])+'u}' for c in capture['calls']]
    text='#include "capture.h"\nconst struct linux_observation linux_calls[LINUX_CALLS]={\n'+',\n'.join(rows)+'\n};\n'
    text+='const uint32_t linux_masks[LINUX_CALLS+1]={'+','.join(str(v)+'u' for v in [initial['umask']]+[c['umask_after'] for c in capture['calls']])+'};\n'
    if profile_for(capture) in ('credentials','fsgid','group-setters','getgroups','setgroups','setgroups-denied','capabilities','capget','prctl','fsuid','setresuid','uid-setters','credential-setters'):
        _,states=projection(capture)
        header=header.replace('#endif\n','struct linux_credential_snapshot {uint32_t gids[2][4],active;uint64_t generation,epochs[2];};\nextern const struct linux_credential_snapshot linux_credentials[LINUX_CALLS+1];\n#endif\n')
        def snapshot(s):return '{{'+','.join('{'+','.join(str(v)+'u' for v in node)+'}' for node in s['pool'])+'},'+str(s['active'])+'u,'+integer(s['generation'])+',{'+','.join(integer(v) for v in s['epochs'])+'}}'
        text+='const struct linux_credential_snapshot linux_credentials[LINUX_CALLS+1]={\n'+',\n'.join(snapshot(s) for s in states)+'\n};\n'
        (sources/'capture.h').write_text(header)
    if profile_for(capture) in ('setgroups','setgroups-denied','capabilities','capget','prctl','fsuid','setresuid','uid-setters','credential-setters'):
        header=header.replace('#endif\n','extern const uint32_t linux_inputs[LINUX_CALLS][8];\nstruct linux_group_snapshot {int32_t usage,ngroups;uint32_t gid[4];};\nstruct linux_group_state {struct linux_group_snapshot pool[2];uint32_t links[2];};\nextern const struct linux_group_state linux_groups[LINUX_CALLS+1];\n#endif\n')
        text+='const uint32_t linux_inputs[LINUX_CALLS][8]={\n'+',\n'.join('{'+','.join(str(v)+'u' for v in c['input_words'])+'}' for c in capture['calls'])+'\n};\n'
        def group_state(s):return '{{'+','.join('{'+str(p['usage'])+','+str(p['ngroups'])+',{'+','.join(str(v)+'u' for v in p['gid'])+'}}' for p in s['group_pool'])+'},{'+','.join(str(v)+'u' for v in s['credential_groups'])+'}}'
        text+='const struct linux_group_state linux_groups[LINUX_CALLS+1]={\n'+',\n'.join(group_state(s) for s in states)+'\n};\n'
        (sources/'capture.h').write_text(header)
    if profile_for(capture) in ('capabilities','capget','prctl','fsuid','setresuid','uid-setters','credential-setters'):
        header=header.replace('#endif\n','extern const uint64_t linux_capabilities[LINUX_CALLS+1][2][5];\n#endif\n')
        text+='const uint64_t linux_capabilities[LINUX_CALLS+1][2][5]={\n'+',\n'.join('{'+','.join('{'+','.join(integer(v) for v in caps)+'}' for caps in s['capabilities'])+'}' for s in states)+'\n};\n'
        (sources/'capture.h').write_text(header)
    if profile_for(capture) in ('prctl','fsuid','setresuid','uid-setters','credential-setters'):
        header=header.replace('#endif\n','extern const uint32_t linux_securebits[LINUX_CALLS+1][2];\n#endif\n')
        text+='const uint32_t linux_securebits[LINUX_CALLS+1][2]={\n'+',\n'.join('{'+','.join(str(v)+'u' for v in state['securebits'])+'}' for state in states)+'\n};\n'
        (sources/'capture.h').write_text(header)
    if profile_for(capture) in ('fsuid','setresuid','uid-setters','credential-setters'):
        header=header.replace('#endif\n','extern const uint32_t linux_fsuids[LINUX_CALLS+1][2];\n#endif\n')
        text+='const uint32_t linux_fsuids[LINUX_CALLS+1][2]={\n'+',\n'.join('{'+','.join(str(v)+'u' for v in state['fsuid'])+'}' for state in states)+'\n};\n'
        (sources/'capture.h').write_text(header)
    if profile_for(capture) in ('setresuid','uid-setters','credential-setters'):
        header=header.replace('#endif\n','extern const uint32_t linux_uids[LINUX_CALLS+1][2][3];\n#endif\n')
        text+='const uint32_t linux_uids[LINUX_CALLS+1][2][3]={\n'+',\n'.join('{'+','.join('{'+','.join(str(v)+'u' for v in slot)+'}' for slot in state['uids'])+'}' for state in states)+'\n};\n'
        (sources/'capture.h').write_text(header)
    if profile_for(capture) in ('uid-setters','credential-setters'):
        header=header.replace('#endif\n','extern const uint32_t linux_user_links[LINUX_CALLS+1][2][2];\n#endif\n')
        text+='const uint32_t linux_user_links[LINUX_CALLS+1][2][2]={\n'+',\n'.join('{'+','.join('{'+','.join(str(v)+'u' for v in slot)+'}' for slot in state['user_links'])+'}' for state in states)+'\n};\n'
        (sources/'capture.h').write_text(header)
    if profile_for(capture) in ('fd-dup','file-io','file-positioned','fd-control','close-range','fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):
        _,states=projection(capture)
        header=header.replace('#endif\n','struct linux_fd_snapshot {uint32_t slots[8],next_fd;uint64_t open_fds,cloexec;int64_t counts[2];};\nextern const struct linux_fd_snapshot linux_fds[LINUX_CALLS+1];\n#endif\n')
        text+='const struct linux_fd_snapshot linux_fds[LINUX_CALLS+1]={\n'+',\n'.join('{'+ '{'+','.join(str(v)+'u' for v in s['slots'])+'},'+str(s['next_fd'])+'u,'+integer(s['open_fds'])+','+integer(s['cloexec'])+',{'+','.join(str(v) for v in s['counts'])+'}}' for s in states)+'\n};\n'
        (sources/'capture.h').write_text(header)
    if profile_for(capture) in ('file-io','file-positioned','fd-control','close-range','fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):
        header=header.replace('#endif\n','extern const uint32_t linux_inputs[LINUX_CALLS][8];\nstruct linux_file_snapshot {int64_t size,pos;uint8_t bytes[64];};\nextern const struct linux_file_snapshot linux_file_data[LINUX_CALLS+1];\n#endif\n')
        text+='const uint32_t linux_inputs[LINUX_CALLS][8]={\n'+',\n'.join('{'+','.join(str(v)+'u' for v in c['input_words'])+'}' for c in capture['calls'])+'\n};\n'
        text+='const struct linux_file_snapshot linux_file_data[LINUX_CALLS+1]={\n'+',\n'.join('{'+str(s['file']['size'])+','+str(s['file']['pos'])+',{'+','.join(str(v) for v in s['file']['bytes'])+'}}' for s in states)+'\n};\n'
        (sources/'capture.h').write_text(header)
    if profile_for(capture) in ('fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):
        header=header.replace('#endif\n','extern const uint32_t linux_stat_words[LINUX_CALLS][32];\nextern const uint64_t linux_stat_blocks[LINUX_CALLS+1];\n#endif\n')
        (sources/'capture.h').write_text(header)
        text+='const uint64_t linux_stat_blocks[LINUX_CALLS+1]={'+','.join(integer(s['file']['blocks']) for s in states)+'};\n'
        text+='const uint32_t linux_stat_words[LINUX_CALLS][32]={\n'+',\n'.join('{'+','.join(str(v)+'u' for v in c['stat_words'])+'}' for c in capture['calls'])+'\n};\n'
    if profile_for(capture) in ('fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):
        header=header.replace('#endif\n','extern const uint32_t linux_inode_modes[LINUX_CALLS+1][2];\n#endif\n')
        (sources/'capture.h').write_text(header)
        text+='const uint32_t linux_inode_modes[LINUX_CALLS+1][2]={\n'+',\n'.join('{'+','.join(str(v)+'u' for v in s['inode_modes'])+'}' for s in states)+'\n};\n'
    if profile_for(capture) in ('fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):
        header=header.replace('#endif\n','extern const uint32_t linux_inode_owners[LINUX_CALLS+1][2][2];\n#endif\n')
        (sources/'capture.h').write_text(header)
        text+='const uint32_t linux_inode_owners[LINUX_CALLS+1][2][2]={\n'+',\n'.join('{'+','.join('{'+','.join(str(v)+'u' for v in pair)+'}' for pair in s['inode_owners'])+'}' for s in states)+'\n};\n'
    if profile_for(capture) in ('file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):
        header=header.replace('#endif\n','extern const uint64_t linux_file_capabilities[LINUX_CALLS+1][2][5];\nextern const uint64_t linux_file_generations[LINUX_CALLS+1][4];\n#endif\n')
        (sources/'capture.h').write_text(header)
        text+='const uint64_t linux_file_capabilities[LINUX_CALLS+1][2][5]={\n'+',\n'.join('{'+','.join('{'+','.join(integer(v) for v in slot)+'}' for slot in s['file_credentials']['caps'])+'}' for s in states)+'\n};\n'
        text+='const uint64_t linux_file_generations[LINUX_CALLS+1][4]={\n'+',\n'.join('{'+','.join(integer(v) for v in [s['file_credentials']['active'],s['file_credentials']['generation']]+s['file_credentials']['epochs'])+'}' for s in states)+'\n};\n'
    if profile_for(capture) in ('file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):
        header=header.replace('#endif\n','extern const uint32_t linux_file_fsgids[LINUX_CALLS+1][2];\n#endif\n')
        (sources/'capture.h').write_text(header)
        text+='const uint32_t linux_file_fsgids[LINUX_CALLS+1][2]={\n'+',\n'.join('{'+','.join(str(v)+'u' for v in s['file_credentials']['fsgids'])+'}' for s in states)+'\n};\n'
    if profile_for(capture) in ('file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):
        header=header.replace('#endif\n','extern const uint32_t linux_file_fsuids[LINUX_CALLS+1][2];\n#endif\n')
        (sources/'capture.h').write_text(header)
        text+='const uint32_t linux_file_fsuids[LINUX_CALLS+1][2]={\n'+',\n'.join('{'+','.join(str(v)+'u' for v in s['file_credentials']['fsuids'])+'}' for s in states)+'\n};\n'
    if profile_for(capture) in ('file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):
        header=header.replace('#endif\n','struct linux_file_groups {uint32_t links[2];int32_t usage[2],count[2];uint32_t gids[2][4];};\nextern const struct linux_file_groups linux_file_groups[LINUX_CALLS+1];\n#endif\n')
        (sources/'capture.h').write_text(header)
        def group_row(st):
            v=st['file_credentials'];p=v['group_pool'];return '{{'+','.join(str(x) for x in v['group_links'])+'},{'+','.join(str(x['usage']) for x in p)+'},{'+','.join(str(x['ngroups']) for x in p)+'},{'+','.join('{'+','.join(str(n)+'u' for n in x['gid'])+'}' for x in p)+'}}'
        text+='const struct linux_file_groups linux_file_groups[LINUX_CALLS+1]={\n'+',\n'.join(group_row(st) for st in states)+'\n};\n'
    if profile_for(capture) in ('file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):
        header=header.replace('#endif\n','extern const uint32_t linux_file_gids[LINUX_CALLS+1][2][3];\n#endif\n')
        (sources/'capture.h').write_text(header)
        text+='const uint32_t linux_file_gids[LINUX_CALLS+1][2][3]={\n'+',\n'.join('{'+','.join('{'+','.join(str(v)+'u' for v in node)+'}' for node in st['file_credentials']['gids'])+'}' for st in states)+'\n};\n'
    if profile_for(capture) in ('file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):
        header=header.replace('#endif\n','extern const uint32_t linux_file_status[LINUX_CALLS+1][2];\n#endif\n')
        (sources/'capture.h').write_text(header)
        text+='const uint32_t linux_file_status[LINUX_CALLS+1][2]={\n'+',\n'.join('{'+','.join(str(v)+'u' for v in st['file_status'])+'}' for st in states)+'\n};\n'
    if profile_for(capture) in ('file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):
        header=header.replace('#endif\n','extern const uint32_t linux_file_securebits[LINUX_CALLS+1][2];\n#endif\n')
        (sources/'capture.h').write_text(header)
        text+='const uint32_t linux_file_securebits[LINUX_CALLS+1][2]={\n'+',\n'.join('{'+','.join(str(v)+'u' for v in st['file_credentials']['securebits'])+'}' for st in states)+'\n};\n'
    if profile_for(capture) in ('file-credentials','file-rlimit','file-limits','file-setrlimit'):
        header=header.replace('#endif\n','extern const uint32_t linux_file_uids[LINUX_CALLS+1][2][3];\nextern const uint32_t linux_file_user_links[LINUX_CALLS+1][2][2];\n#endif\n')
        (sources/'capture.h').write_text(header)
        for name,key in [('uids','uids'),('user_links','user_links')]:
            width=3 if key=='uids' else 2
            text+='const uint32_t linux_file_'+name+'[LINUX_CALLS+1][2]['+str(width)+']={\n'+',\n'.join('{'+','.join('{'+','.join(str(v)+'u' for v in slot)+'}' for slot in st['file_credentials'][key])+'}' for st in states)+'\n};\n'
    if profile_for(capture)=='file-setrlimit':
        header=header.replace('#endif\n','extern const uint64_t linux_resource_limits[LINUX_CALLS+1][16][2];\n#endif\n')
        (sources/'capture.h').write_text(header)
        text+='const uint64_t linux_resource_limits[LINUX_CALLS+1][16][2]={\n'+',\n'.join('{'+','.join('{'+','.join(integer(v) for v in pair)+'}' for pair in st['resource_limits'])+'}' for st in states)+'\n};\n'
    (sources/'capture.c').write_text(text)

def prepare(args,sources):
    root=Path(__file__).parent;capture,manifest=validate_capture(root/'native')
    if (args.capture/'capture.manifest.json').read_bytes()!=(root/'native/capture.manifest.json').read_bytes() or (args.capture/'capture.json').read_bytes()!=(root/'native/capture.json').read_bytes():raise ValueError('Linux capture input differs from pinned bundle')
    review,found=source_identity(root/'native')
    if profile_for(capture) in ('fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):shutil.copyfile(upstream(root/'native')/'include/uapi/asm-generic/stat.h',sources/'upstream_stat.h')
    if profile_for(capture) in ('file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):shutil.copyfile(upstream(root/'native')/'include/uapi/linux/capability.h',sources/'upstream_capability.h')
    if profile_for(capture) in ('file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):
        shutil.copyfile(upstream(root/'native')/'include/uapi/linux/securebits.h',sources/'upstream_securebits.h')
        filesystem=(upstream(root/'native')/'include/linux/capability.h').read_bytes()
        (sources/'upstream_fs_capability.h').write_bytes(filesystem[:filesystem.index(b'static inline kernel_cap_t cap_drop(')])
    if profile_for(capture) in ('file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):shutil.copyfile(upstream(root/'native')/'include/uapi/asm-generic/fcntl.h',sources/'upstream_fcntl.h')
    if profile_for(capture) in ('file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):shutil.copyfile(upstream(root/'native')/'include/uapi/linux/prctl.h',sources/'upstream_prctl.h')
    for name in ('model.h','models.c','adapter.c','checkpoint-policy.json'):shutil.copyfile(root/name,sources/name)
    if profile_for(capture) in ('capabilities','capget','prctl','fsuid','setresuid','uid-setters','credential-setters'):shutil.copyfile(upstream(root/'native')/'include/uapi/linux/capability.h',sources/'upstream_capability.h')
    if profile_for(capture) in ('prctl','fsuid','setresuid','uid-setters','credential-setters'):
        for name in ('prctl','securebits'):shutil.copyfile(upstream(root/'native')/('include/uapi/linux/'+name+'.h'),sources/('upstream_'+name+'.h'))
    if profile_for(capture) in ('fsuid','setresuid','uid-setters','credential-setters'):
        filesystem=(upstream(root/'native')/'include/linux/capability.h').read_bytes()
        (sources/'upstream_fs_capability.h').write_bytes(filesystem[:filesystem.index(b'static inline kernel_cap_t cap_drop(')])
    declarations=b'\n'.join((v['declaration']+';').encode() for v in found.values() if not v['syscall'])+b'\n' if profile_for(capture) in ('setresuid','uid-setters','credential-setters','fd-dup','file-io','file-positioned','fd-control','close-range','fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else b''
    (sources/'syscalls.c').write_bytes(b'// SPDX-License-Identifier: GPL-2.0\n/* Original reviewed Linux syscall bodies; only SYSCALL_DEFINE wrappers are expanded. */\n#include "model.h"\n'+declarations+b'\n'.join((('long linux_'+n+'('+v['signature']+')' if v['syscall'] else v['declaration'])+'\n').encode()+v['body']+b'\n' for n,v in sorted(found.items(),key=lambda item:item[1]['syscall'])))
    if profile_for(capture) in ('file-io','file-positioned','fd-control','close-range','fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):
        # Linux disables this warning: retain its original signed/unsigned
        # comparisons without weakening diagnostics on the reviewed models.
        # A default kernel build has no -Wextra either: the fd-control bodies keep their unused parameters.
        ignored=b'#pragma GCC diagnostic ignored "-Wunused-parameter"\n' if profile_for(capture) in ('fd-control','file-setrlimit') else b''
        p=sources/'syscalls.c';p.write_bytes(b'#pragma GCC diagnostic push\n#pragma GCC diagnostic ignored "-Wsign-compare"\n'+ignored+p.read_bytes()+b'#pragma GCC diagnostic pop\n')
    capture_sources(root,sources,capture)
    if profile_for(capture)=='fd-control':
        for name,original in FD_CONTROL_ASSEMBLY.items():(sources/name).write_bytes((upstream(root/'native')/original).read_bytes())
        kernel_headers(root,sources,(root/'native/kernel.config').read_text())
        shutil.copyfile(root/'entry-glue.S',sources/'entry-glue.S')
    dependencies=['current task and parent IDs','initial user-namespace credentials','sequential xchg','single-task RCU balance','bounded 32-bit put_user']
    if profile_for(capture) in ('credentials','fsgid','group-setters','getgroups'):dependencies+=['two-slot copy-on-write credential pool','unprivileged group changes','successful credential security hook']
    if profile_for(capture) in ('fsgid','group-setters','getgroups'):dependencies+=['filesystem group changes','credential abort leaves inactive copied slot; no publication']
    if profile_for(capture) in ('group-setters','getgroups'):dependencies+=['saved group ID rules','partially modified candidate may survive abort in inactive pool slot']
    if profile_for(capture)=='getgroups':dependencies+=['fixed supplementary-group object of capacity four','protected native witness guard page; bounded replay copy faults']
    if profile_for(capture)=='setgroups':dependencies+=['two-slot credential and supplementary-list pools; inactive credentials are non-owning snapshots','effective CAP_SETGID and enabled setgroups in initial namespace','capacity-four allocation and insertion sort; duplicate IDs retained','modeled list references released on publication and copy errors; no heap or RCU reclamation','successful supplementary-group security hook','protected native witness guard page; bounded replay read/write faults']
    if profile_for(capture)=='setgroups-denied':dependencies+=['observed absent effective CAP_SETGID persisted in both credential slots','permission rejection precedes size validation, allocation and user-copy access','two bounded list objects and typed credential links remain unchanged on denial','initial namespace permits setgroups; namespace-disabled branches not admitted','native capget probes observe the effective SETGID bit; capget is capture infrastructure']
    if profile_for(capture) in ('capabilities','capget','prctl','fsuid','setresuid','uid-setters','credential-setters'):dependencies+=['effective, permitted, inheritable, bounding and ambient capability sets persisted in both credential slots','original capset version/PID validation and commoncap subset/ambient rules','self-only capability mutation; additional LSM and audit/warning effects modeled as successful/no-op','bounded header/data copies, two credential/list pools, allocation and sorting models','native capget/prctl probes observe all five capability sets; initial namespace']
    if profile_for(capture) in ('capget','prctl','fsuid','setresuid','uid-setters','credential-setters'):dependencies+=['original capget version/NULL-output/PID ordering and commoncap self snapshot','single-task PID lookup: INT32_MAX has no target; balanced RCU and ESRCH','bounded capability serialization and protected-page output fault prefix']
    if profile_for(capture) in ('prctl','fsuid','setresuid','uid-setters','credential-setters'):dependencies+=['prctl syscall route enters original cap_task_prctl directly only for reviewed commoncap options; general sys_prctl wrapper is not exported','original bounding-set drops and ambient operations; securebits and keepcaps persisted across copy/publication','initial effective and permitted CAP_SETPCAP; successful/no-op extra LSM, capability audit and task-superpriv effects','five arguments bound including reserved-argument errors; real/effective/saved UID transitions and exec excluded']
    if profile_for(capture) in ('fsuid','setresuid','uid-setters','credential-setters'):dependencies+=['original setfsuid syscall/helper and commoncap filesystem capability fixup','original kernel-header cap_drop/FS drop/FS raise helpers; full eight-bit filesystem set includes bit 32','initial namespace UID mapping, effective CAP_SETUID authorization, stable real/effective/saved UIDs','private nonmutating setfsuid(-1) observes active FSUID; both copied slots persisted; securebits control and lock fixup suppression']
    if profile_for(capture) in ('setresuid','uid-setters','credential-setters'):
        dependencies=[v.replace('real/effective/saved UID transitions and exec excluded','exec excluded').replace('stable real/effective/saved UIDs','mutable real/effective/saved UIDs') for v in dependencies]
        dependencies+=['original setresuid syscall/helper, set_user, flag_nproc_exceeded and set_cred_ucounts; original commoncap RES fixups','four fixed reviewed UID identities 1001/0/9001/9002 with typed user/accounting links and balanced model credential references','unlimited NPROC; exec/fork, external accounting consumers and allocation exhaustion excluded','private getresuid observes all active user IDs after each call; copied slots and accounting graph checked independently']
    if profile_for(capture) in ('uid-setters','credential-setters'):dependencies+=['original setuid and setreuid wrappers/helpers; privileged all-ID replacement and unprivileged real/saved-ID admission','setreuid saved-ID rules use old real ID; same-ID/all-sentinel requests publish and repair FSUID','permission rejection may leave partially modified inactive UID fields with unchanged accounting links; aborted ownership remains balanced']
    if profile_for(capture)=='credential-setters':dependencies+=['original setgid/setregid/setresgid/setfsgid wrappers/helpers share the existing UID/capability/list/accounting context','live effective CAP_SETGID authorizes privileged group changes; UID and FSUID capability effects control later group admission','group-ID LSM hook modeled as successful; group changes do not alter capability sets, supplementary IDs or UID-keyed accounting','scalar GID slots copied on every credential preparation; denied setregid may retain a changed inactive real GID before effective rejection','native getresgid/setfsgid probes bind evolving scalar groups and filesystem GID after every call']
    if profile_for(capture)=='fd-dup':dependencies+=['original dup/dup3/close wrappers, allocation, lookup, installation, replacement and removal bodies','single-task fixed 64-slot fd table with checked RLIMIT_NOFILE=8; no resize, fork, exec, larval slots or concurrent file-table changes','two preconstructed file classes: shared console descriptors 0..2 and one readonly /init seed; native F_GETFD/F_GETFL probes observe admitted slots and flags','file identities inferred from construction and duplication rules; native probes do not attest physical open-file-description pointers','typed nullable descriptor links, file reference counts, next_fd and open/close-on-exec/full bitmaps persist; stale close-on-exec bits in closed slots retained','f_mode projects only the consumed FMODE_BACKING bit (Linux bit 25), zero for both admitted file classes; original raw lookup uses mask zero','atomic references and balanced locks/RCU modeled sequentially; reference-zero releases have no external consumer','filp_flush boundary modeled successful: no driver flush, notifications, POSIX locks, delayed fput or host services; file data/offsets/path lookup excluded']
    if profile_for(capture) in ('file-io','file-positioned','fd-control','close-range','fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):dependencies+=['original dup/dup3/close bodies and descriptor helpers; original read/write wrappers and ksys helpers, file_ppos, ksys_lseek, unsigned_offsets, vfs_setpos, generic_file_llseek_size and rw_verify_area','fixed 64-slot table and checked NOFILE 8; one shared console file and one RW memfd seed, native F_GET_SEALS identifies the regular class','64-byte in-memory regular-file callback with persistent size and contents; file offset/version stored on shared file object, so dup aliases share position','VFS read/write and llseek indirect filesystem callbacks modeled with direct bounded implementations; successful permission/notification hooks, no audit or task I/O-accounting consumers','modeled fdget_pos uses balanced strong references; sequential execution excludes f_pos concurrency and delayed release','SEEK_SET/CUR/END admitted; data/hole seek, append, pathname lookup, independent opens, resize, fork/exec and console I/O excluded','native pread observes contents without changing position; lseek(0,CUR) observes shared position; closed last-reference state is a model snapshot, not native memory','guard-page fault prefixes and zero-count/EOF/error precedence checked against native memfd behavior; seek may exceed capacity but admitted writes stay within 64 bytes']
    if profile_for(capture) in ('file-positioned','fd-control','close-range','fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):
        dependencies=[v.replace('original read/write wrappers and ksys helpers','original read/write/positioned-I/O wrappers and ksys helpers') for v in dependencies]
        dependencies+=['original pread64/pwrite64 wrappers and ksys helpers; negative position precedes fd lookup, positioned transfers use a local offset and leave shared f_pos unchanged','original ftruncate wrapper, do_sys_ftruncate and do_ftruncate; typed file-path/dentry/inode/superblock graph persists across restore','projected inode types distinguish console from regular file; regular RW mode includes PREAD/PWRITE, append is clear and ARM64 O_LARGEFILE is set','balanced superblock write boundaries, successful truncate security hook and direct do_truncate model; no idmapped namespace, notification/privilege-clearing consumer or filesystem allocation','truncate length 0..64; removed tail bytes cleared before re-extension; truncation preserves all aliases shared f_pos, even beyond new EOF']
    if profile_for(capture) in ('fd-control','close-range','fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):dependencies+=(['original fcntl syscall entry, check_fcntl_cmd and do_fcntl; original fdget/fdget_raw/fdput and the __fget_light single-owner fast path over a bound files->count; security_file_fcntl walks the constant BPF-only LSM hook list, and the callees of commands outside the five (setfl, locks, owners, leases, notify, pipe, seals, rw hints, DUPFD_QUERY) are reviewed fault boundaries','original read/write/truncate path: fdget_pos, vfs_read/vfs_write, shmem read_iter/write_iter/write_begin/write_end/setattr, the page-cache lookup and undo (xarray, folio batches), generic_perform_write, notify_change and the atime/mtime/ctime and i_version updates; operation-table calls (f_op, a_ops, i_op, s_op) are rewritten to reviewed dispatch models; original user-ID mapping over the bound namespace maps, close flush (filp_flush, dnotify_flush, locks_remove_posix), descriptor bit search, the iov_iter user-copy chain (always-inline steps named by an enumeration) and the five LSM hook walks over a constant hook table whose entries are BPF no-op defaults; per-CPU writer counts, rwsems, folio flag atomics, the __arch_copy_* primitives (bounded to the observed user object), folio allocation and page-cache deletion are reviewed models; one order-0 folio holds the first 64 bytes of the page; the coarse clock and inode timestamps are unobserved model state'] if profile_for(capture)=='fd-control' else ['fcntl syscall entry and five-command dispatch are reviewed models, not the original general sys_fcntl/do_fcntl bodies; raw lookup and balanced strong release preserve native EBADF precedence'])+['original f_dupfd, get_close_on_exec and set_close_on_exec helpers; commands F_DUPFD/F_DUPFD_CLOEXEC/F_GETFD/F_SETFD/F_GETFL only, plus one observed unknown-command EINVAL','descriptor-local close-on-exec bits survive resumes independently of aliases; F_GETFL reads fixed shared file flags; F_SETFL, leases, locks, seals, owner/signals, O_PATH and rejecting LSM hooks excluded','original minimum-descriptor allocation and reference acquisition use the existing fixed table and NOFILE 8 contract; integer fd/command/from narrowing checked against native Linux']
    if profile_for(capture) in ('close-range','fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):dependencies+=['original close_range wrapper, __close_range, last_fd, __range_close and __range_cloexec bodies retained; syscall arguments narrow to unsigned 32-bit before range/flag validation','range close releases only live descriptors inclusively, ignores holes and preserves stale close-on-exec bits; original filp_close releases the final file reference','CLOSE_RANGE_CLOEXEC sets bitmap slots even when closed, clamped to the fixed 64-slot table; high closed-slot bits persist as model bookkeeping and are not native memory observations','sequential scheduler hints modeled without scheduling; flush/reschedule callbacks check that file_lock is released, and need_resched is false','CLOSE_RANGE_UNSHARE excluded; unshare/table-replacement/put-files boundaries fail if reached; no shared table, fork, exec or allocator semantics admitted']
    if profile_for(capture) in ('fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):dependencies+=['original newfstat/vfs_fstat/vfs_getattr/cp_new_stat bodies; modeled direct filesystem getattr and successful security hook','separate guarded 128-byte caller object; all non-clock stat bytes including padding are verified; workload discards offsets 72..119 only after successful calls','timestamps and their consumers are outside this workload contract; no runtime clock or captured post-call stat oracle','entry inode identity/mode/ownership/device/block-size observed by native fstat and persisted in both inode objects; memfd has at most one 4 KiB page','positive writes allocate eight 512-byte blocks; truncate-to-zero frees them; extension without writes does not allocate; native private fstat checks block count after every call','stat ABI layout reference is a selected Linux v6.11 generic header; layout and offsets checked by static assertions and native Linux 6.10.14 output']
    if profile_for(capture) in ('fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):dependencies+=['original fchmod/vfs_fchmod/chmod_common bodies; low nine permission bits, unsigned fd and 16-bit mode narrowing, retained inode type bits','native constructor transfers the memfd to effective UID 1002 before credential drop; private fstat observes mode after every call','reviewed initial-namespace owner check and direct notify_change attribute update; console owned by another UID returns EPERM','typed mount links, balanced write and inode-lock models; no delegation, ACLs, special mode bits, idmaps, extra LSM rejection, pathname lookup or clock consumers','permission changes affect the shared inode; existing open-file descriptions retain their read/write capability']
    if profile_for(capture)=='fchown':dependencies+=['original fchown/ksys_fchown/vfs_fchown/chown_common and setattr_vfsuid/setattr_vfsgid bodies; initial-namespace scalar ID conversions and no delegation','fixed effective UID/FSUID 1002, effective group/FSGID 2002 and explicitly seeded/observed supplementary group zero; private capget observes zero effective capabilities','reviewed notify_change owner and group-membership rules: same owner, old group, effective group or observed supplementary group; UID and foreign-group changes reject atomically','native private stat probes observe live inode UID/GID after every call; aliases share ownership, mode and existing-open I/O access','ordinary modes only, so set-ID and file-capability removal have no consumers; no CAP_CHOWN grant, arbitrary namespace/group changes, ACLs, privileged ownership transfer or timestamp consumers']
    if profile_for(capture)=='fchown-capable':dependencies+=['original fchown wrapper and five ownership helpers retained; reviewed initial-namespace notify_change capability admission, not original setattr_prepare', 'fixed UID/FSUID 1002, group/FSGID 2002, seeded supplementary group zero; private capget observes effective CAP_CHOWN only, stored in credential checkpoint state', 'CAP_CHOWN permits foreign UID/GID transfer and nonowner reclamation; CAP_FOWNER is absent, so fchmod denies after transfer; aliases retain shared ownership and existing open I/O rights', 'private native stat probes check UID/GID after each call; mode and ownership changes resume jointly with application CPU/memory', 'no capability setters or credential changes in this file profile; permitted reboot capability is private capture teardown, not an effective runtime capability', 'ordinary modes only; no set-ID, ACL, file-capability, delegation, idmap, pathname or timestamp consumers']
    if profile_for(capture) in ('file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):dependencies+=['original capset, cap_validate_magic, mk_kernel_cap, cap_inh_is_capped and cap_capset bodies, added to the retained file operations', 'two-slot credential preparation/publication/abort model; both capability sets and inactive snapshots persist with typed active links and generation counters', 'live effective CAP_CHOWN controls ownership transfer; live CAP_FOWNER controls nonowner chmod; permitted-set removal prevents regain', 'fixed UID/FSUID 1002 and group/FSGID 2002 with supplementary group zero; private capget observes effective/permitted/inheritable sets after every call; initial bounding/ambient observed with prctl', 'successful security/audit boundaries; no task ID/group setters, namespace changes, capget replay route, prctl replay route, allocation exhaustion or concurrent credential users', 'ordinary inode modes only, no ACL, delegation, file-capability or timestamp consumers; existing open-file access remains fixed']
    if profile_for(capture) in ('file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):
        dependencies=[v.replace('group/FSGID 2002','effective group 2002 and mutable filesystem GID').replace('no task ID/group setters','no task UID or real/effective/saved GID setters') for v in dependencies]
        dependencies+=['original setfsgid/__sys_setfsgid bodies reuse the live two-slot capset credential pool', 'fixed real/effective/saved groups 2001/2002/2003, mutable filesystem GID copied with every candidate; invalid IDs, same-ID and denied requests return the old filesystem GID without publication', 'notify_change group membership reads current filesystem GID, not effective GID; supplementary group zero and current inode group are also admitted', 'CAP_SETGID is absent from the admitted permitted set; arbitrary filesystem groups cannot be granted by capset; group LSM hook modeled successful', 'native private setfsgid(-1) observes the filesystem group after every call without preparation or mutation; both inactive and active slots checked across resumes']
    if profile_for(capture) in ('file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):
        dependencies=[v.replace('fixed UID/FSUID 1002','fixed effective UID 1002 and mutable filesystem UID').replace('no task UID or real/effective/saved GID setters','no real/effective/saved UID/GID setters') for v in dependencies]
        dependencies+=['original setfsuid/__sys_setfsuid, commoncap UID fixup and three filesystem-capability inline helpers; securebits fixed zero and observed at native entry', 'notify_change ownership uses live filesystem UID; real/effective/saved UIDs 1001/1002/0 remain fixed; absent CAP_SETUID silently denies foreign filesystem users', 'entering filesystem UID zero raises only filesystem bits present in permitted set; leaving zero drops effective filesystem bits; both credential slots retain FSUID, FSGID and capabilities across every publication', 'private invalid-ID setfsuid(-1) observes filesystem UID after every call; no preparation for invalid IDs; effective UID queried independently by application']
    if profile_for(capture) in ('file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):
        dependencies=[v.replace('with supplementary group zero','with live supplementary groups initially zero').replace('supplementary group zero and current inode group','live supplementary membership and current inode group').replace('no real/effective/saved UID/GID setters','no real/effective/saved UID/GID setters').replace('CAP_SETGID is absent from the admitted permitted set; arbitrary filesystem groups cannot be granted by capset; group LSM hook modeled successful','CAP_SETGID is initially permitted and controlled by capset; permanently removed before inherited filesystem-GID recipes; group LSM hook modeled successful') for v in dependencies]
        dependencies+=['original getgroups/setgroups, user-copy, list replacement and publication helpers; two capacity-four group objects with sorted duplicates, empty lists and released partial input snapshots', 'typed group links in both credentials; inactive copies are non-owning snapshots; active/prepared/caller allocations own checked references', 'live effective CAP_SETGID precedes size/copy validation; capability drop and permitted removal reject setgroups; filesystem UID zero raises filesystem capabilities but does not grant absent effective SETGID', 'notify_change checks active supplementary membership; original current inode group and FSGID also admitted; EUID/FSUID owner rules retained', 'initial supplementary list zero is explicitly seeded and observed; native private getgroups observes membership after every call; group-pool reference counts and inactive snapshots are model bookkeeping']
    if profile_for(capture) in ('file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):
        dependencies=[v.replace('fixed real/effective/saved groups 2001/2002/2003','mutable real/effective/saved groups initially 2001/2002/2003').replace('no real/effective/saved UID/GID setters','no real/effective/saved UID setters') for v in dependencies]
        dependencies+=['original setgid/setregid/setresgid wrappers and helpers share capability, FSUID/FSGID and supplementary-list state', 'live effective SETGID admits foreign scalar group IDs; unprivileged saved-ID rules and partial inactive setregid edits retained; setresgid denials and genuine no-ops return before preparation', 'explicit same-EGID setresgid repairs a distinct FSGID; all-sentinel no-op preserves it; real/effective/saved groups copied by every credential publisher', 'native private getresgid observes all three IDs after every application call; dynamic values drive later getgid/getegid/getresgid and file permission checks; both slots checked after joint restore']
    if profile_for(capture) in ('file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):
        dependencies=[v.replace('five-command dispatch','six-command dispatch').replace('data/hole seek, append, pathname lookup','data/hole seek, pathname lookup').replace('F_GETFL reads fixed shared file flags; F_SETFL,','F_GETFL reads live shared file flags;').replace('commands F_DUPFD/F_DUPFD_CLOEXEC/F_GETFD/F_SETFD/F_GETFL only','commands F_DUPFD/F_DUPFD_CLOEXEC/F_GETFD/F_SETFD/F_GETFL/F_SETFL') for v in dependencies]
        dependencies+=['F_SETFL entry/helper and append filesystem behavior are explicit reviewed models, not original setfl or generic_file_write_iter bodies; original descriptor and read/write/positioned bodies retained unchanged','pinned Linux v6.10 flag declarations; APPEND, NONBLOCK and NOATIME mutable per open description, shared by aliases; ignored access/create/truncate/cloexec/high bits cannot alter descriptor bits or file data','new NOATIME requires live FSUID ownership or effective FOWNER; retaining or clearing it needs no new ownership check; no clock consumers','append relocates nonempty ordinary and positioned writes to EOF; pwrite preserves shared f_pos; zero and failed writes preserve position; direct/asynchronous/pipe/disk-specific flags excluded','private native F_GETFL observes all live descriptors after each call; released file flags and ownership graph remain model bookkeeping']
    if profile_for(capture) in ('file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):
        dependencies=[v.replace('capget replay route, ','') for v in dependencies]
        dependencies+=['original capget/cap_get_target_pid/cap_capget read the currently published credential; application versions 1/2/3, null-output negotiation, current/absent/negative PID, aliased header/output and guarded partial copies checked against native Linux','single-task target lookup admits only current PID and guaranteed absent INT32_MAX; task traversal, ptrace, other tasks and namespaces excluded','shared copy_to_user boundary resolves either the 32-byte scalar/capability caller object or the separate 128-byte stat object, preserving the writable prefix on faults; queries never publish or prepare credentials']
    if profile_for(capture) in ('file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):
        dependencies=[v.replace('prctl replay route, ','') for v in dependencies]
        dependencies+=['prctl enters original cap_task_prctl/cap_prctl_drop only for seven reviewed commoncap options; general sys_prctl and other LSM consumers excluded; original dispatch prefix retained as routing evidence','temporary permitted SETPCAP is captured at entry; application regains it to exercise bounding/ambient/securebit operations, then permanently removes it before the inherited session','live securebits cloned into both active/inactive credential slots; NO_SETUID_FIXUP suppresses original FSUID capability fixups; locked KEEP_CAPS and a high bounding-bit drop persist across the inherited file session','ambient capabilities are retained/queryable but do not grant immediate file permissions; capset intersects ambient with permitted/inheritable sets; no exec consumers','private prctl reads bind bounding/ambient/securebits after every call; no new persisted fields, no host services']
    if profile_for(capture) in ('file-credentials','file-rlimit','file-limits','file-setrlimit'):
        dependencies+=["original setuid/setreuid/setresuid wrappers and helpers, set_user/flag_nproc_exceeded/set_cred_ucounts retained; live UID/FSUID and commoncap ID/RE/RES effects join the file session","four bounded real-UID user/accounting objects; prepare/commit/abort balance strong refs, inactive aborted UID edits retain nonowning original accounting links","native unlimited NPROC is set and observed; no fork/exec or external process-accounting consumer","temporary permitted SETUID is captured at entry and removed after a UID setup block restores initial IDs, file ownership, capabilities and securebits; inherited file/prctl session then continues","private getresuid observes active IDs after every call; UID-driven effective/ambient changes affect subsequent file checks while already-open data access remains valid"]
    if profile_for(capture)=='file-limits':
        dependencies+=['original getrlimit wrapper retained; do_prlimit is an explicit query-only model, not its original general body','all 16 AArch64 LP64 resource soft/hard pairs are seeded from validated native entry state and persist as typed scalar fields; NPROC/NOFILE consumers share those objects','resource setters, PID traversal, CPU timers, scheduling and concurrent limit updates excluded; queries alone do not enable those facilities','native private getrlimit observes all 16 pairs after every application call; valid-resource EFAULT and invalid-resource EINVAL ordering verified']
    if profile_for(capture)=='file-rlimit':
        dependencies+=['original getrlimit wrapper retained; do_prlimit is an explicit query-only model, not its original general body','NPROC and NOFILE soft/hard pairs persist as typed scalar fields; rlimit consumers read the same objects','NPROC remains unlimited and NOFILE remains eight; other valid resources, limit setters, PID traversal, timers, scheduler and concurrent limit updates excluded','16-byte AArch64 LP64 rlimit layout checked statically and against native getrlimit; native private queries observe both pairs after every call']
    if profile_for(capture)=='file-setrlimit':
        dependencies+=['original getrlimit/setrlimit wrappers and do_prlimit helper retained unchanged; mutable pairs belong to a typed signal object','sequential task lock and no-extra-LSM setrlimit boundary modeled explicitly; live initial-namespace capability check','NOFILE model ceiling eight is equivalent for this recipe with no CAP_SYS_RESOURCE and hard limit initially eight; native sysctl_nr_open is not captured','updates admitted for STACK, CORE, NOFILE and MEMLOCK; CPU timers, other resource enforcement, other tasks and concurrent updates excluded','all 16 live pairs are observed natively after every call and retained through the generic object-graph codec']
    return dict(identity=dict(kind='linux-aarch64-reviewed-syscall-projection',reviewed_source=review,native_kernel=manifest['identity'],native_source_build_attested=False,modeled_dependencies=dependencies),checkpoint=capture,metadata=dict(kernel_image_sha256=manifest['identity']['kernel_image_sha256']),sources=['models.c','syscalls.c'],assembly_sources=['entry-glue.S',*sorted(FD_CONTROL_ASSEMBLY)] if profile_for(capture)=='fd-control' else [],assembly_options={n:FD_CONTROL_ASSEMBLY_OPTIONS for n in FD_CONTROL_ASSEMBLY} if profile_for(capture)=='fd-control' else {},headers=(['model.h','upstream_stat.h','upstream_capability.h','upstream_securebits.h','upstream_fs_capability.h'] if profile_for(capture) in ('file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else ['model.h','upstream_stat.h','upstream_capability.h'] if profile_for(capture) in ('file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else ['model.h','upstream_stat.h'] if profile_for(capture) in ('fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else ['model.h','upstream_capability.h','upstream_prctl.h','upstream_securebits.h','upstream_fs_capability.h'] if profile_for(capture) in ('fsuid','setresuid','uid-setters','credential-setters') else ['model.h','upstream_capability.h','upstream_prctl.h','upstream_securebits.h'] if profile_for(capture) in ('prctl','fsuid','setresuid','uid-setters','credential-setters') else ['model.h','upstream_capability.h'] if profile_for(capture) in ('capabilities','capget','prctl','fsuid','setresuid','uid-setters','credential-setters') else ['model.h'])+(['upstream_fcntl.h'] if profile_for(capture) in ('file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else [])+(['upstream_prctl.h'] if profile_for(capture) in ('file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else []),adapter_source='adapter.c',data_source='capture.c',checkpoint_policy='checkpoint-policy.json',required_syscalls=sorted({c['number'] for c in capture['calls']}),capture_manifest='capture.manifest.json',expected_result=dict(call_count=len(capture['calls']),scalar_width=64,input_rejections=4))
