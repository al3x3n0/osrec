"""Bounded entry-state transcript result ABI (30), alongside legacy ABI 8."""
import struct

MAX_CALLS=256
LEGACY_CALLS=7
HEADER_BYTES=128
RECORD_BYTES=8


def transcript_bytes(words,result_bytes):
    if len(words)!=32 or words[0]!=0x4f535243 or words[1]!=30 or words[2] not in (2,3):
        raise ValueError('invalid entry-state transcript header')
    count=words[5]
    if not LEGACY_CALLS<count<=MAX_CALLS:
        raise ValueError('entry-state transcript has invalid call count')
    expected=HEADER_BYTES+RECORD_BYTES*count
    if (words[10:14]!=(count,RECORD_BYTES,HEADER_BYTES,1) or result_bytes!=expected or
        any(words[i] for i in (*range(14,24),*range(26,32)))):
        raise ValueError('entry-state transcript layout differs from bounded result symbol')
    if (words[9] not in (0,1) or words[24] not in (0,1) or words[8]>=count or
        any(words[i]>count for i in (4,6,7,25)) or words[4]!=words[7]):
        raise ValueError('entry-state transcript flags/progress differ')
    return expected


def decode_transcript(raw):
    if len(raw)<HEADER_BYTES:raise ValueError('incomplete entry-state transcript header')
    words=struct.unpack_from('<32I',raw)
    transcript_bytes(words,len(raw))
    calls=[{'number':number,'raw_bits':bits} for number,bits in struct.iter_unpack('<2I',raw[HEADER_BYTES:])]
    result={'session':'entry_state','call_count':words[5],'states_restored':words[6],
            'states_verified':words[7],'last_invocation':words[8],'write_effects':bool(words[9]),
            'continuous_replay':bool(words[24]),'entry_states_checked':words[25],'actual_calls':calls,
            'transcript':{'version':1,'offset':HEADER_BYTES,'record_bytes':RECORD_BYTES,
                          'capacity':words[5],'result_bytes':len(raw)}}
    if not words[9]:result['unchanged_states']=words[7]
    return result
