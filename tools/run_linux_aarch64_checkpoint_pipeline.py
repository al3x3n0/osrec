#!/usr/bin/env python3
"""Native ARM64 Linux capture -> pinned slices -> C gateway checkpoint chain."""
import argparse
import json
import shutil
import struct
from pathlib import Path
from types import SimpleNamespace
from capture_linux_aarch64 import capture,reviewed_adapter,digest,ROOT,INTEGRATION
from prepare_linux_aarch64_port import build_bundle
from export_syscall_slices import export
from verify_syscall_slices import verify_matrix
from run_c_application_checkpoint_chain import run_pipeline,verify_chain,ordinals
from application_pause import verify_joint
from slice_port_bundle import verify_published

FORMAT='osrec-linux-aarch64-checkpoint-pipeline-v1'

def saved_state(chain,kernel,captured):
    codec=kernel['checkpoint_codec'];offsets={f['path']:codec['header_bytes']+f['wire_offset'] for f in codec['fields'] if 'wire_offset' in f}
    review=reviewed_adapter();profile=review.profile_for(captured);_,projected=review.projection(captured)
    rows=[]
    for i,ordinal in enumerate(chain['pause_ordinals']):
        joint=verify_joint(chain['out']/('stage-'+str(i))/'checkpoint',kernel);raw=joint['record']
        mask=struct.unpack_from('<i',raw,offsets['fs.umask'])[0]
        extra={}
        if profile in ('credentials','fsgid','group-setters','getgroups','setgroups','setgroups-denied','capabilities','capget','prctl','fsuid','setresuid','uid-setters','credential-setters'):
            state=projected[ordinal]
            credential_id=struct.unpack_from('<Q',raw,offsets['task.cred'])[0]
            generation=struct.unpack_from('<Q',raw,offsets['credential_generation'])[0]
            epochs=list(struct.unpack_from('<2Q',raw,offsets['credential_slot_generation']))
            pool=[];fsuids=[];user_ids=[]
            for s in range(2):
                prefix='credential_pool['+str(s)+'].'
                slot={n:struct.unpack_from('<I',raw,offsets[prefix+n])[0] for n in ('uid','euid','suid','fsuid','gid','egid','sgid','fsgid')}
                if [slot[n] for n in ('uid','euid','suid')]!=(state['uids'][s] if profile in ('setresuid','uid-setters','credential-setters') else captured['initial']['uids']) or slot['fsuid']!=(state['fsuid'][s] if profile in ('fsuid','setresuid','uid-setters','credential-setters') else captured['initial']['uids'][1]):raise ValueError('saved Linux user credentials differ')
                fsuids.append(slot['fsuid']);user_ids.append([slot[n] for n in ('uid','euid','suid')])
                pool.append([slot[n] for n in ('gid','egid','sgid','fsgid')])
            if credential_id!=state['active']+1 or generation!=state['generation'] or epochs!=state['epochs'] or pool!=state['pool']:raise ValueError('saved Linux credential pool differs from projection')
            uids=user_ids[credential_id-1];gids=pool[credential_id-1][:3]
            fsgid=pool[credential_id-1][3]
            if gids!=captured['calls'][ordinal-1]['gids_after'] or fsgid!=captured['calls'][ordinal-1]['fsgid_after']:raise ValueError('saved Linux group credentials differ from native capture')
            if profile in ('fsuid','setresuid','uid-setters','credential-setters') and fsuids[credential_id-1]!=captured['calls'][ordinal-1]['fsuid_after']:raise ValueError('saved Linux filesystem user differs from native capture')
            extra=dict(fsgid=fsgid,credential_id=credential_id,generation=generation,slot_generations=epochs,credential_pool=pool)
            if profile in ('fsuid','setresuid','uid-setters','credential-setters'):extra.update(fsuid=fsuids[credential_id-1],credential_fsuids=fsuids)
            if profile in ('setresuid','uid-setters','credential-setters'):
                if uids!=captured['calls'][ordinal-1]['uids_after']:raise ValueError('saved Linux user IDs differ from native capture')
                identities=[1001,0,9001,9002];user_links=[];account_links=[];accounts=[]
                for s in range(2):
                    prefix='credential_pool['+str(s)+'].'
                    user_links.append(struct.unpack_from('<Q',raw,offsets[prefix+'user'])[0]);account_links.append(struct.unpack_from('<Q',raw,offsets[prefix+'ucounts'])[0])
                for j,uid in enumerate(identities):
                    up='user_pool['+str(j)+'].';cp='ucounts_pool['+str(j)+'].'
                    account=dict(uid=struct.unpack_from('<I',raw,offsets[cp+'uid'])[0],usage=struct.unpack_from('<i',raw,offsets[cp+'usage'])[0])
                    if account!={'uid':uid,'usage':int(uid==uids[0])} or struct.unpack_from('<I',raw,offsets[up+'uid'])[0]!=uid or struct.unpack_from('<i',raw,offsets[up+'usage'])[0]!=account['usage']:raise ValueError('saved Linux user accounting differs')
                    accounts.append(account)
                expected_users=[v[0]+1 for v in state['user_links']] if profile in ('uid-setters','credential-setters') else [identities.index(ids[0])+1 for ids in user_ids]
                expected_accounts=[v[1]+1 for v in state['user_links']] if profile in ('uid-setters','credential-setters') else expected_users
                if user_links!=expected_users or account_links!=expected_accounts or struct.unpack_from('<I',raw,offsets['task.flags'])[0] or struct.unpack_from('<I',raw,offsets['parent.flags'])[0]:raise ValueError('saved Linux accounting links/flags differ')
                extra.update(credential_uids=user_ids,user_links=user_links,accounting_links=account_links,user_accounting=accounts)
        elif profile in ('file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):
            state=projected[ordinal]['file_credentials'];active=struct.unpack_from('<Q',raw,offsets['task.cred'])[0]
            generation=struct.unpack_from('<Q',raw,offsets['credential_generation'])[0]
            epochs=list(struct.unpack_from('<2Q',raw,offsets['credential_slot_generation']))
            pool=[];gid_pool=[];file_uid_pool=[]
            for j in range(2):
                prefix='credential_pool['+str(j)+'].'
                users=[struct.unpack_from('<I',raw,offsets[prefix+n])[0] for n in ('uid','euid','suid')]
                groups=[struct.unpack_from('<I',raw,offsets[prefix+n])[0] for n in ('gid','egid','sgid')]
                gid_pool.append(groups);file_uid_pool.append(users)
                if users!=(state['uids'][j] if profile in ('file-credentials','file-rlimit','file-limits','file-setrlimit') else captured['initial']['uids']) or groups!=(state['gids'][j] if profile in ('file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else captured['initial']['gids']):raise ValueError('saved Linux file credentials differ')
                pool.append([struct.unpack_from('<Q',raw,offsets[prefix+'cap_'+n+'.val'])[0] for n in ('effective','permitted','inheritable','bset','ambient')])
            if active!=state['active']+1 or generation!=state['generation'] or epochs!=state['epochs'] or pool!=state['caps'] or pool[active-1][:3]!=captured['calls'][ordinal-1]['file_caps_after']:raise ValueError('saved Linux live file capability state differs')
            if profile in ('file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):
                fsgids=[struct.unpack_from('<I',raw,offsets['credential_pool['+str(j)+'].fsgid'])[0] for j in range(2)]
                if fsgids!=state['fsgids'] or fsgids[active-1]!=captured['calls'][ordinal-1]['file_fsgid_after']:raise ValueError('saved Linux file filesystem groups differ')
                extra.update(file_fsgids=fsgids,fsgid=fsgids[active-1])
            if profile in ('file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):
                fsuids=[struct.unpack_from('<I',raw,offsets['credential_pool['+str(j)+'].fsuid'])[0] for j in range(2)]
                securebits=[struct.unpack_from('<I',raw,offsets['credential_pool['+str(j)+'].securebits'])[0] for j in range(2)]
                if fsuids!=state['fsuids'] or fsuids[active-1]!=captured['calls'][ordinal-1]['file_fsuid_after'] or securebits!=(state['securebits'] if profile in ('file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else [captured['initial']['file_securebits']]*2):raise ValueError('saved Linux file filesystem users differ')
                extra.update(file_fsuids=fsuids,fsuid=fsuids[active-1],credential_securebits=securebits)
                if profile in ('file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):
                    observation=pool[active-1][3:]+[securebits[active-1]]
                    if observation!=captured['calls'][ordinal-1]['file_prctl_after']:raise ValueError('saved Linux file prctl state differs from native capture')
                    extra['file_prctl_after']=observation
            if profile in ('file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):
                links=[struct.unpack_from('<Q',raw,offsets['credential_pool['+str(j)+'].group_info'])[0] for j in range(2)];groups=[]
                for j in range(2):
                    prefix='group_pool['+str(j)+'].';groups.append(dict(usage=struct.unpack_from('<i',raw,offsets[prefix+'usage'])[0],ngroups=struct.unpack_from('<i',raw,offsets[prefix+'ngroups'])[0],gid=list(struct.unpack_from('<4I',raw,offsets[prefix+'gid']))))
                if links!=[j+1 for j in state['group_links']] or groups!=state['group_pool']:raise ValueError('saved Linux file supplementary pools differ')
                live=groups[links[active-1]-1];values=live['gid'][:live['ngroups']]
                if values!=captured['calls'][ordinal-1]['file_groups_after']:raise ValueError('saved Linux live file supplementary groups differ')
                extra.update(file_group_links=links,file_group_pool=groups,supplementary_groups=values)
            uids=file_uid_pool[active-1] if profile in ('file-credentials','file-rlimit','file-limits','file-setrlimit') else captured['initial']['uids'];gids=gid_pool[active-1] if profile in ('file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else captured['initial']['gids']
            if profile in ('file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):
                if gids!=captured['calls'][ordinal-1]['file_gids_after']:raise ValueError('saved Linux live scalar file group IDs differ')
                extra['file_gid_pool']=gid_pool
            extra.update(credential_id=active,generation=generation,slot_generations=epochs,file_capability_pool=pool,ownership_effective_caps=pool[active-1][0])
            if profile in ('file-credentials','file-rlimit','file-limits','file-setrlimit'):
                if uids!=captured['calls'][ordinal-1]['file_uids_after']:raise ValueError('saved Linux live file user IDs differ')
                identities=[1001,0,9001,9002];user_links=[];account_links=[];accounts=[]
                for slot in range(2):
                    prefix='credential_pool['+str(slot)+'].'
                    user_links.append(struct.unpack_from('<Q',raw,offsets[prefix+'user'])[0]);account_links.append(struct.unpack_from('<Q',raw,offsets[prefix+'ucounts'])[0])
                for j,uid in enumerate(identities):
                    up='user_pool['+str(j)+'].';cp='ucounts_pool['+str(j)+'].'
                    account=dict(uid=struct.unpack_from('<I',raw,offsets[cp+'uid'])[0],usage=struct.unpack_from('<i',raw,offsets[cp+'usage'])[0])
                    if account!={'uid':uid,'usage':int(uid==uids[0])} or struct.unpack_from('<I',raw,offsets[up+'uid'])[0]!=uid or struct.unpack_from('<i',raw,offsets[up+'usage'])[0]!=account['usage'] or not any(f['path']==cp+'ns' and f['policy']=='self_reference' and f.get('target')=='user_ns' for f in codec['fields']):raise ValueError('saved Linux file user accounting differs')
                    accounts.append(account)
                if user_links!=[v[0]+1 for v in state['user_links']] or account_links!=[v[1]+1 for v in state['user_links']] or struct.unpack_from('<I',raw,offsets['task.flags'])[0] or struct.unpack_from('<I',raw,offsets['parent.flags'])[0]:raise ValueError('saved Linux file accounting links/flags differ')
                extra.update(file_uid_pool=file_uid_pool,user_links=user_links,accounting_links=account_links,user_accounting=accounts)

        else:
            # Credential IDs are plain integers or kuid_t/kgid_t values (creds.uid.val).
            ids=lambda names:[struct.unpack_from('<I',raw,offsets['creds.'+n] if 'creds.'+n in offsets else offsets['creds.'+n+'.val'])[0] for n in names]
            uids=ids(('uid','euid','suid'));gids=ids(('gid','egid','sgid'))
            if uids!=captured['initial']['uids'] or gids!=captured['initial']['gids']:raise ValueError('saved Linux state differs from native capture')
        if profile in ('file-rlimit','file-limits','file-setrlimit'):
            limits=[[struct.unpack_from('<Q',raw,offsets[('process_signal.rlim[' if profile=='file-setrlimit' else 'resource_limits[')+str(j)+'].'+name])[0] for name in ('rlim_cur','rlim_max')] for j in range(16 if profile in ('file-limits','file-setrlimit') else 2)]
            expected_limits=projected[ordinal]['resource_limits'] if profile=='file-setrlimit' else captured['initial']['rlimits'] if profile=='file-limits' else [captured['initial']['nproc_limit'],captured['initial']['nofile_limit']]
            if limits!=expected_limits or limits!=captured['calls'][ordinal-1]['file_all_rlimits_after' if profile in ('file-limits','file-setrlimit') else 'file_rlimits_after']:raise ValueError('saved Linux resource limits differ')
            extra['resource_limits']=limits
        if profile=='fchown-capable':
            effective=struct.unpack_from('<Q',raw,offsets['creds.cap_effective'])[0]
            if effective!=captured['initial']['ownership_effective_caps']:raise ValueError('saved Linux ownership capability differs')
            extra['ownership_effective_caps']=effective
        if profile in ('fd-dup','file-io','file-positioned','fd-control','close-range','fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):
            state=projected[ordinal];slots=[];counts=[];flags=[]
            for fd in range(64):slots.append(struct.unpack_from('<Q',raw,offsets['files.fdtab.fd['+str(fd)+']'])[0])
            for j in range(2):
                prefix='file_pool['+str(j)+'].'
                counts.append(struct.unpack_from('<q',raw,offsets[prefix+'f_count'])[0]);flags.append(struct.unpack_from('<I',raw,offsets[prefix+'f_flags'])[0])
                # fd-control models the live f_mode bits its original vfs_read/vfs_write test (FMODE_CAN_READ/CAN_WRITE).
                mode=(0x6001f if j else 0x60003) if profile=='fd-control' else (31 if j else 1<<21) if profile in ('file-positioned','close-range','fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else (7 if j else 1<<21) if profile=='file-io' else 0
                if struct.unpack_from('<I',raw,offsets[prefix+'object_id'])[0]!=j+1 or struct.unpack_from('<I',raw,offsets[prefix+'f_mode'])[0]!=mode:raise ValueError('saved Linux file class differs')
            next_fd=struct.unpack_from('<I',raw,offsets['files.next_fd'])[0]
            open_fds=struct.unpack_from('<Q',raw,offsets['files.fdtab.open_fds'])[0];cloexec=struct.unpack_from('<Q',raw,offsets['files.fdtab.close_on_exec'])[0]
            if struct.unpack_from('<Q',raw,offsets['files.fdt'])[0]!=1 or slots!=state['slots']+[0]*56 or counts!=state['counts'] or flags!=(state['file_status'] if profile in ('file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else captured['initial']['file_flags']) or next_fd!=state['next_fd'] or open_fds!=state['open_fds'] or cloexec!=state['cloexec'] or struct.unpack_from('<I',raw,offsets['files.fdtab.max_fds'])[0]!=64 or struct.unpack_from('<Q',raw,offsets['files.fdtab.full_fds_bits'])[0] or struct.unpack_from('<i',raw,offsets['files.resize_in_progress'])[0]:raise ValueError('saved Linux descriptor graph differs')
            observed=[[v,int(bool(cloexec&(1<<fd)))] if v else [0,0] for fd,v in enumerate(slots[:8])]
            if observed!=captured['calls'][ordinal-1]['fds_after']:raise ValueError('saved Linux descriptors differ from native capture')
            if profile in ('file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):
                live=[flags[v-1] if v else None for v in slots[:8]]
                if live!=captured['calls'][ordinal-1]['fd_status_after']:raise ValueError('saved Linux file-status flags differ from native capture')
                extra['fd_status_after']=live
            extra.update(fd_slots=slots[:8],file_counts=counts,file_flags=flags,next_fd=next_fd,open_fds=open_fds,cloexec=cloexec,fd_capacity=64,nofile_limit=limits[7][0] if profile=='file-setrlimit' else 8)
            if profile in ('file-io','file-positioned','fd-control','close-range','fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):
                file=dict(size=struct.unpack_from('<q',raw,offsets['file_data.size' if 'file_data.size' in offsets else 'inode_pool[1].i_size'])[0],pos=struct.unpack_from('<q',raw,offsets['file_pool[1].f_pos'])[0],bytes=list(raw[offsets['file_data.bytes']:offsets['file_data.bytes']+64]))
                if profile in ('fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):file['blocks']=struct.unpack_from('<Q',raw,offsets['inode_pool[1].blocks'])[0]
                if profile in ('fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):
                    file.update(uid=struct.unpack_from('<I',raw,offsets['inode_pool[1].uid'])[0],gid=struct.unpack_from('<I',raw,offsets['inode_pool[1].gid'])[0])
                if profile in ('fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):file['mode']=struct.unpack_from('<I',raw,offsets['inode_pool[1].i_mode'])[0]
                if file!=state['file'] or (2 in slots and file!=captured['calls'][ordinal-1]['file_after']) or (2 not in slots and captured['calls'][ordinal-1]['file_after'] is not None):raise ValueError('saved Linux file bytes/offset differ from native capture/projection')
                if struct.unpack_from('<q',raw,offsets['file_pool[0].f_pos'])[0] or any(struct.unpack_from('<Q',raw,offsets['file_pool['+str(j)+'].f_version'])[0] for j in range(2)):raise ValueError('saved Linux inactive file position/version differs')
                extra.update(file=file)
                if profile in ('file-positioned','fd-control','close-range','fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):
                    paths=[];dentries=[];inodes=[]
                    for j in range(2):
                        paths.append(struct.unpack_from('<Q',raw,offsets['file_pool['+str(j)+'].f_path.dentry'])[0])
                        dentries.append(struct.unpack_from('<Q',raw,offsets['dentry_pool['+str(j)+'].d_inode'])[0])
                        prefix='inode_pool['+str(j)+'].'
                        inodes.append(dict(mode=struct.unpack_from('<I',raw,offsets[prefix+'i_mode'])[0],append=struct.unpack_from('<I',raw,offsets[prefix+'append'])[0]))
                    if paths!=[1,2] or dentries!=[1,2] or (inodes!=[dict(mode=(state['inode_modes'][j] if profile in ('fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else m['mode']),append=0) for j,m in enumerate(review.stat_metadata(captured['initial']))] if profile in ('fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit') else inodes!=[dict(mode=0o20000,append=0),dict(mode=0o100000,append=0)]):raise ValueError('saved Linux inode graph differs')
                    if profile in ('fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):
                        metadata=[]
                        for j,m in enumerate(review.stat_metadata(captured['initial'])):
                            got={n:struct.unpack_from('<Q' if n in ('ino','blocks') else '<I',raw,offsets['inode_pool['+str(j)+'].'+('i_mode' if n=='mode' else n)])[0] for n in m}
                            want=dict(m,blocks=state['file']['blocks'] if j else m['blocks'])
                            if profile in ('fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):want['mode']=state['inode_modes'][j]
                            if profile in ('fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):want.update(zip(('uid','gid'),state['inode_owners'][j]))
                            if got!=want:raise ValueError('saved Linux inode metadata differs')
                            metadata.append(got)
                        extra['inode_metadata']=metadata
                    if profile in ('fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'):
                        mounts=[struct.unpack_from('<Q',raw,offsets['file_pool['+str(j)+'].f_path.mnt'])[0] for j in range(2)]
                        ids=[struct.unpack_from('<I',raw,offsets['mount_pool['+str(j)+'].object_id'])[0] for j in range(2)]
                        if mounts!=[1,2] or ids!=[1,2]:raise ValueError('saved Linux mount links differ')
                        extra.update(file_mounts=mounts,mount_ids=ids)
                    extra.update(file_dentries=paths,dentry_inodes=dentries,inodes=inodes)
        if profile=='getgroups':
            count=struct.unpack_from('<i',raw,offsets['supplementary_groups.ngroups'])[0]
            group_ids=list(struct.unpack_from('<4I',raw,offsets['supplementary_groups.gid']))
            expected=captured['initial']['groups']
            if count!=len(expected) or group_ids!=expected+[0]*(4-len(expected)) or captured['calls'][ordinal-1]['groups_after']!=expected:raise ValueError('saved Linux supplementary groups differ from native capture')
            extra.update(supplementary_groups=group_ids[:count],supplementary_capacity=4)
        if profile in ('setgroups','setgroups-denied','capabilities','capget','prctl','fsuid','setresuid','uid-setters','credential-setters'):
            state=projected[ordinal];links=[];groups=[]
            for s in range(2):
                prefix='group_pool['+str(s)+'].'
                usage,count=struct.unpack_from('<i',raw,offsets[prefix+'usage'])[0],struct.unpack_from('<i',raw,offsets[prefix+'ngroups'])[0]
                groups.append(dict(usage=usage,ngroups=count,gid=list(struct.unpack_from('<4I',raw,offsets[prefix+'gid']))))
                links.append(struct.unpack_from('<Q',raw,offsets['credential_pool['+str(s)+'].group_info'])[0])
            if profile=='setgroups-denied':
                caps=[struct.unpack_from('<I',raw,offsets['credential_pool['+str(s)+'].cap_setgid'])[0] for s in range(2)]
                if caps!=[captured['initial']['cap_setgid']]*2 or caps[credential_id-1]!=captured['calls'][ordinal-1]['cap_setgid_after']:raise ValueError('saved Linux effective SETGID capability differs from native capture')
                extra.update(cap_setgid=caps[credential_id-1],credential_cap_setgid=caps)
            if profile in ('capabilities','capget','prctl','fsuid','setresuid','uid-setters','credential-setters'):
                names=('effective','permitted','inheritable','bset','ambient')
                caps=[[struct.unpack_from('<Q',raw,offsets['credential_pool['+str(s)+'].cap_'+n+'.val'])[0] for n in names] for s in range(2)]
                if caps!=state['capabilities'] or caps[credential_id-1]!=captured['calls'][ordinal-1]['capabilities_after']:raise ValueError('saved Linux capability pool differs from native capture/projection')
                extra.update(capabilities=caps[credential_id-1],credential_capabilities=caps)
            if profile in ('prctl','fsuid','setresuid','uid-setters','credential-setters'):
                secure=[struct.unpack_from('<I',raw,offsets['credential_pool['+str(s)+'].securebits'])[0] for s in range(2)]
                if secure!=state['securebits'] or secure[credential_id-1]!=captured['calls'][ordinal-1]['securebits_after']:raise ValueError('saved Linux securebits differ from native capture/projection')
                extra.update(securebits=secure[credential_id-1],credential_securebits=secure)
            allowed=struct.unpack_from('<I',raw,offsets['user_ns.setgroups_allowed'])[0]
            if groups!=state['group_pool'] or links!=[v+1 for v in state['credential_groups']] or allowed!=1:raise ValueError('saved Linux supplementary pool differs from projection')
            p=groups[links[credential_id-1]-1];active_groups=p['gid'][:p['ngroups']]
            if active_groups!=captured['calls'][ordinal-1]['groups_after']:raise ValueError('saved Linux supplementary list differs from native capture')
            extra.update(supplementary_groups=active_groups,supplementary_capacity=4,group_pool=groups,credential_group_ids=links,setgroups_allowed=allowed)
        if mask!=captured['calls'][ordinal-1]['umask_after']:raise ValueError('saved Linux mask differs from native capture')
        rows.append(dict(ordinal=ordinal,umask=mask,uids=uids,gids=gids,record_sha256=digest(raw),**extra))
    return rows

def verify_pipeline(directory):
    directory=Path(directory).resolve();report=json.loads((directory/'workflow.json').read_text())
    if report.get('format')!=FORMAT or report.get('status')!='verified':raise ValueError('not a verified Linux pipeline')
    actual={str(p.relative_to(directory)) for p in directory.rglob('*') if p.is_file() and p!=directory/'workflow.json'}
    if actual!=set(report['artifact_hashes']):raise ValueError('Linux pipeline artifact set differs')
    for name,expected in report['artifact_hashes'].items():
        if digest((directory/name).read_bytes())!=expected:raise ValueError('Linux pipeline artifact hash differs: '+name)
    captured,manifest=reviewed_adapter().validate_capture(directory/'native')
    if report.get('profile','minimal')!=reviewed_adapter().profile_for(captured):raise ValueError('Linux pipeline profile differs')
    kernel=json.loads((directory/'kernel/manifest.json').read_text())
    verify_published(directory/'kernel/port-inputs',kernel)
    chain=verify_chain(directory/'chain')
    matrix=json.loads((directory/'kernel-qemu/verification-matrix.json').read_text())
    states=saved_state(dict(out=directory/'chain',pause_ordinals=chain['pause_ordinals']),kernel,captured)
    if report['saved_state']!=states or report['kernel_release']!=manifest['identity']['kernel_release'] or report['logical_calls']!=chain['logical_calls'] or report['runtime_host_interaction'] is not False:raise ValueError('Linux pipeline summary differs from evidence')
    if matrix.get('status')!='verified' or len(matrix['executions'])!=4 or report['qemu_matrix_executions']!=4+sum(s['qemu_executions'] for s in chain['stages']):raise ValueError('Linux pipeline QEMU matrix differs')
    expected=dict(source_release=kernel['source_identity']['reviewed_source']['release'],native_source_build_attested=kernel['source_identity']['native_source_build_attested'],syscalls=kernel['port']['roots'],context_bytes=kernel['state_layout']['OSREC_SLICE_STATE_BYTES'],record_bytes=kernel['checkpoint_codec']['record_bytes'],pause_ordinals=chain['pause_ordinals'])
    if any(report.get(name)!=value for name,value in expected.items()) or kernel['source_identity']['native_kernel']!=manifest['identity'] or kernel['source_identity']['reviewed_source']!=manifest['reviewed_source_identity']:raise ValueError('Linux pipeline source/state contract differs')
    modes={(e['loading_mode'],e['start']) for e in matrix['executions']}
    if modes!={('elf','el1'),('elf','el3'),('raw','el1'),('raw','el3')} or matrix['image_manifest_sha256']!=digest((directory/'kernel/manifest.json').read_bytes()) or matrix['result_sha256']!=digest((directory/'kernel/target-result.bin').read_bytes()) or matrix['runtime_host_interaction'] is not False or kernel['target_observations']['guest_host_services']:raise ValueError('Linux kernel QEMU evidence differs')
    for row in chain['stages']:
        if row['observations']['guest_host_services']:raise ValueError('Linux replay used guest host services')
    return report

def run(args):
    out=Path(args.out).resolve()
    if out.exists():raise FileExistsError(out)
    if getattr(args,'capture',None):
        original=Path(args.capture).resolve()
        if out.is_relative_to(original):raise ValueError('pipeline output overlaps native capture')
        existing,_=reviewed_adapter().validate_capture(original)
        if getattr(args,'profile',None) not in (None,reviewed_adapter().profile_for(existing)):raise ValueError('requested Linux profile differs from capture')
    out.mkdir(parents=True)
    native=out/'native'
    if getattr(args,'capture',None):shutil.copytree(original,native)
    else:capture(SimpleNamespace(kernel_image=args.kernel_image,config=args.config,out=native,llvm_bin=args.llvm_bin,qemu=args.qemu,timeout=args.timeout,accel=args.accel,profile=getattr(args,'profile',None) or 'minimal'))
    captured,capture_manifest=reviewed_adapter().validate_capture(native)
    profile=reviewed_adapter().profile_for(captured)
    if getattr(args,'profile',None) not in (None,profile):raise ValueError('requested Linux profile differs from capture')
    defaults={'minimal':[8,15,19],'credentials':[8,23,26,35,41],'fsgid':[43,46,48,54,58,61],'group-setters':[63,67,70,80,87,93],'getgroups':[67,95,100,106,109,111],'setgroups':[27,31,33,37,43,50],'setgroups-denied':[22,31,35,40,53,59],'capabilities':[23,27,35,43,52,58],'capget':[24,28,54,61,71,78]}
    names={name:i for i,(name,_,_) in enumerate(reviewed_adapter().prctl_plan(reviewed_adapter().recipes('minimal')))}
    defaults['prctl']=[names[n]+1 for n in ('raise_gid','drop_gid','cannot_restore_inheritable_gid','lock_securebits','drop_permitted_setpcap','empty_groups')]
    fsnames={name:i for i,(name,_,_) in enumerate(reviewed_adapter().fsuid_plan())}
    defaults['fsuid']=[fsnames[n]+1 for n in ('drop_with_ambient','foreign_uid_denied','suppressed_drop','restore_remaining_permitted','lock_fs_fixup','locked_drop_after_capset')]
    uidnames={name:i for i,(name,_,_) in enumerate(reviewed_adapter().setresuid_plan())}
    defaults['setresuid']=[uidnames[n]+1 for n in ('drop_effective_root','real_to_saved_root','real_to_foreign_privileged','drop_all_root_ids_keepcaps','drop_all_with_suppression','locked_drop_without_cap_setuid')]
    setternames={name:i for i,(name,_,_) in enumerate(reviewed_adapter().uid_setters_plan())}
    defaults['uid-setters']=[setternames[n]+1 for n in ('unprivileged_real_setuid','saved_only_real_denied','partial_real_then_effective_denied','privileged_nonroot_setuid_keepcaps','suppressed_real_and_effective','locked_partial_abort')]
    allnames={name:i for i,(name,_,_) in enumerate(reviewed_adapter().credential_setters_plan())}
    defaults['credential-setters']=[allnames[n]+1 for n in ('partial_real_gid_then_effective_denied','drop_effective_uid','sentinels_keep_divergent_fsgid','remove_permitted_setgid','move_final_accounting_user','final_partial_gid_abort')]
    fdnames={name:i for i,(name,_) in enumerate(reviewed_adapter().fd_dup_plan())}
    defaults['fd-dup']=[fdnames[n]+1 for n in ('table_full','close_cloexec','regular_replace_console_cloexec','close_original_seed','truncated_close','last_regular_reference')]
    ionames={n:i for i,(n,_,_) in enumerate(reviewed_adapter().file_io_plan())}
    defaults['file-io']=[ionames[n]+1 for n in ('write_sparse','read_partial_fault','write_partial_fault','original_writes_alias_offset','close_original_seed','last_regular_reference')]
    positionednames={n:i for i,(n,_,_) in enumerate(reviewed_adapter().file_positioned_plan())}
    defaults['file-positioned']=[positionednames[n]+1 for n in ('pwrite_partial_fault','shrink_below_position','truncate_empty_keeps_position','pwrite_alias_keeps_shared_position','shrink_via_alias','truncate_surviving_alias')]
    controlnames={n:i for i,(n,_,_) in enumerate(reviewed_adapter().fd_control_plan())}
    defaults['fd-control']=[controlnames[n]+1 for n in ('clear_seed_cloexec','set_alias_cloexec','full_minimum_allocation','clear_original_with_alias_set','duplicate_surviving_cloexec','last_regular_reference')]
    rangenames={n:i for i,(n,_,_) in enumerate(reviewed_adapter().close_range_plan())}
    defaults['close-range']=[rangenames[n]+1 for n in ('mark_full_tail','close_middle_aliases','restore_range_aliases','bulk_close_aliases','range_last_reference','mark_after_last_release')]
    statnames={n:i for i,(n,_,_) in enumerate(reviewed_adapter().fstat_plan())}
    defaults['fstat']=[statnames[n]+1 for n in ('stat_after_sparse_write','stat_empty_unallocated','stat_extended_unallocated','stat_alias_same_inode','stat_last_surviving_alias','stat_after_last_release')]
    chmodnames={n:i for i,(n,_,_) in enumerate(reviewed_adapter().fchmod_plan())}
    defaults['fchmod']=[chmodnames[n]+1 for n in ('stat_mode_600','stat_mode_none','stat_mode_readonly','stat_mode_shared_alias','stat_mode_restored_alias','stat_mode_after_release')]
    ownernames={n:i for i,(n,_,_) in enumerate(reviewed_adapter().fchown_plan())}
    capnames={n:i for i,(n,_,_) in enumerate(reviewed_adapter().fchown_capable_plan())}
    defaults['fchown-capable']=[capnames[n]+1 for n in ('stat_privileged_transfer','stat_privileged_sentinels','stat_privileged_no_access','stat_privileged_alias_group','stat_privileged_restored_alias','stat_privileged_after_release')]
    defaults['fchown']=[ownernames[n]+1 for n in ('stat_group_2002','stat_group_sentinels','stat_group_no_access','stat_group_alias_2002','stat_group_denied_atomic','stat_owner_after_release')]
    livecapnames={n:i for i,(n,_,_) in enumerate(reviewed_adapter().file_capabilities_plan())}
    defaults['file-capabilities']=[livecapnames[n]+1 for n in ('file_caps_drop_chown','file_caps_subset_denied','file_caps_stat_foreign_mode','file_caps_drop_fowner','file_caps_stat_alias','file_caps_stat_permitted_removed')]
    fsnames={n:i for i,(n,_,_) in enumerate(reviewed_adapter().file_fsgid_plan())}
    defaults['file-fsgid']=[fsnames[n]+1 for n in ('file_fsgid_stat_real','file_fsgid_same_no_publish','file_fsgid_stat_saved','file_fsgid_stat_effective','file_fsgid_stat_alias_saved','file_fsgid_alias_refresh_dropped')]
    funames={n:i for i,(n,_,_) in enumerate(reviewed_adapter().file_fsuid_plan())}
    defaults['file-fsuid']=[funames[n]+1 for n in ('file_fsuid_stat_real_denied','file_fsuid_stat_root_foreign','file_fsuid_stat_dropped','file_fsuid_stat_owner','file_fsuid_stat_alias_group','file_fsuid_stat_alias_restored')]
    gnames={n:i for i,(n,_,_) in enumerate(reviewed_adapter().file_groups_plan())}
    defaults['file-groups']=[gnames[n]+1 for n in ('file_groups_stat_duplicates','file_groups_stat_no_effective','file_groups_stat_empty','file_groups_query_after_fault','file_groups_stat_alias','file_groups_stat_restored')]
    sgnames={n:i for i,(n,_,_) in enumerate(reviewed_adapter().file_group_setters_plan())}
    defaults['file-group-setters']=[sgnames[n]+1 for n in ('file_group_setters_stat_privileged','file_group_setters_stat_real','file_group_setters_query_partial_abort','file_group_setters_stat_repair','file_group_setters_stat_nondefault_copy','file_group_setters_stat_restored')]
    flag_names={n:i for i,(n,_,_) in enumerate(reviewed_adapter().file_status_plan())}
    defaults['file-status']=[flag_names['file_status_'+n]+1 for n in ('stat_append','stat_pwrite','stat_alias','stat_reopened','stat_noatime_denied','stat_restored')]
    query_names={n:i for i,(n,_,_) in enumerate(reviewed_adapter().file_capget_plan())}
    defaults['file-capget']=[query_names['file_capget_'+n]+1 for n in ('fowner_gain','fowner_drop','partial_output','root_gain','root_drop','final')]
    control_names={n:i for i,(n,_,_) in enumerate(reviewed_adapter().file_prctl_plan())}
    defaults['file-prctl']=[control_names[n]+1 for n in ('file_prctl_ambient_raise','file_prctl_suppressed_root','file_prctl_root_fixup','file_prctl_lock_keepcaps','file_capget_root_gain','file_prctl_final_securebits')]
    credential_names={n:i for i,(n,_,_) in enumerate(reviewed_adapter().file_credentials_plan())}
    defaults['file-credentials']=[credential_names[n]+1 for n in ('file_credentials_move_accounting_user','file_credentials_partial_real_then_effective_denied','file_credentials_drop_all_root_keepcaps','file_credentials_suppressed_nonroot','file_credentials_restore_entry_caps','file_prctl_final_securebits')]
    limit_names={n:i for i,(n,_,_) in enumerate(reviewed_adapter().file_rlimit_plan())}
    defaults['file-rlimit']=[limit_names['file_rlimit_'+n]+1 for n in ('partial_nofile','partial_nproc','accounting_changed_nproc','inactive_abort_nproc','table_full_nofile','last_release_nproc')]
    all_limit_names={n:i for i,(n,_,_) in enumerate(reviewed_adapter().file_limits_plan())}
    defaults['file-limits']=[all_limit_names['file_limits_'+n]+1 for n in ('entry_3','partial_4','partial_11','aborted_3','table_full_7','released_15')]
    set_limit_names={n:i for i,(n,_,_) in enumerate(reviewed_adapter().file_setrlimit_plan())}
    defaults['file-setrlimit']=[set_limit_names['file_setrlimit_'+n]+1 for n in ('dup_denied','dup_restored','wide_core','lower_memlock_hard','raise_memlock_hard_denied','raise_nofile_hard_denied')]
    pauses=getattr(args,'pause_ordinals',None) or defaults[profile]
    port=build_bundle(native,out/'port')
    kernel=export(SimpleNamespace(arch='aarch64',capture=native,kernel_root=INTEGRATION/'upstream',out=out/'kernel',port=port,llvm_bin=args.llvm_bin,qemu=args.qemu,entry_address=0x40200000,result_address=0x40180000))
    print('Linux returning slices verified',flush=True)
    matrix=verify_matrix(out/'kernel',out/'kernel-qemu',qemu=args.qemu,llvm_bin=args.llvm_bin)
    chain=run_pipeline(SimpleNamespace(slices=out/'kernel',source=[out/'port/application.c'],spec=out/'port/spec.json',pause_ordinals=pauses,out=out/'chain',llvm_bin=args.llvm_bin,qemu=args.qemu))
    states=saved_state(dict(out=out/'chain',pause_ordinals=pauses),kernel,captured)
    report=dict(format=FORMAT,status='verified',profile=profile,kernel_release=capture_manifest['identity']['kernel_release'],source_release=kernel['source_identity']['reviewed_source']['release'],native_source_build_attested=False,logical_calls=chain['logical_calls'],pause_ordinals=pauses,qemu_matrix_executions=len(matrix['executions'])+sum(s['qemu_executions'] for s in chain['stages']),context_bytes=kernel['state_layout']['OSREC_SLICE_STATE_BYTES'],record_bytes=kernel['checkpoint_codec']['record_bytes'],saved_state=states,syscalls=kernel['port']['roots'],runtime_host_interaction=False,construction_sha256={n:digest((ROOT/'tools'/n).read_bytes()) for n in ('capture_linux_aarch64.py','minimal_ext2.py','prepare_linux_aarch64_port.py','run_linux_aarch64_checkpoint_pipeline.py')},artifact_hashes={str(p.relative_to(out)):digest(p.read_bytes()) for p in sorted(out.rglob('*')) if p.is_file()})
    (out/'workflow.json').write_text(json.dumps(report,indent=2)+'\n');verify_pipeline(out)
    return report

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    group=parser.add_mutually_exclusive_group(required=True);group.add_argument('--capture',type=Path);group.add_argument('--kernel-image',type=Path);group.add_argument('--verify',type=Path)
    parser.add_argument('--profile',choices=('minimal','credentials','fsgid','group-setters','getgroups','setgroups','setgroups-denied','capabilities','capget','prctl','fsuid','setresuid','uid-setters','credential-setters','fd-dup','file-io','file-positioned','fd-control','close-range','fstat','fchmod','fchown','fchown-capable','file-capabilities','file-fsgid','file-fsuid','file-groups','file-group-setters','file-status','file-capget','file-prctl','file-credentials','file-rlimit','file-limits','file-setrlimit'));parser.add_argument('--config',type=Path);parser.add_argument('--out',type=Path);parser.add_argument('--pause-ordinals',type=ordinals);parser.add_argument('--llvm-bin',type=Path,default=Path('/opt/homebrew/opt/llvm@16/bin'));parser.add_argument('--qemu',default='qemu-system-aarch64');parser.add_argument('--accel',choices=('tcg','hvf'),default='tcg');parser.add_argument('--timeout',type=int,default=300)
    args=parser.parse_args()
    if args.verify:report=verify_pipeline(args.verify)
    else:
        if args.out is None:parser.error('--out is required')
        report=run(args)
    print(json.dumps({k:report[k] for k in ('status','kernel_release','logical_calls','qemu_matrix_executions','context_bytes','record_bytes','saved_state')},indent=2))

if __name__=='__main__':main()
