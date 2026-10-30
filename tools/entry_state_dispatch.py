"""Generate typed replay calls; dependency implementations remain caller supplied."""
import re

from entry_state import snapshot_providers

IDENTIFIER=re.compile(r'^[A-Za-z_][A-Za-z_0-9]*$')
RESULTS={'u32':'unsigned int','i32':'int','void':'void'}


def generate_dispatch(plans,calls,dispatch):
    if (not isinstance(dispatch,dict) or set(dispatch)!={'format','sites'} or
        dispatch['format']!='osrec-entry-dispatch-v1' or not isinstance(dispatch['sites'],list) or not dispatch['sites']):
        raise ValueError('generated dispatch requires osrec-entry-dispatch-v1 sites')
    sites={};roots=set()
    for site in dispatch['sites']:
        if (not isinstance(site,dict) or set(site)!={'root','number','return_kind'} or
            not isinstance(site['root'],str) or not IDENTIFIER.fullmatch(site['root']) or site['root'].startswith('osrec_') or
            site['root'] not in plans or site['root'] in roots or type(site['number']) is not int or
            not 0<=site['number']<=0xffffffff or site['number'] in sites or site['return_kind'] not in RESULTS):
            raise ValueError('dispatch sites require unique plan roots/routes and u32, i32 or void returns')
        sites[site['number']]=site;roots.add(site['root'])
    lines=['/* Generated typed invocation dispatch. Dependency models remain explicit. */',
           '_Static_assert(sizeof(unsigned int)==4 && sizeof(int)==4,"dispatch scalar ABI differs");',
           '_Static_assert((int)UINT32_MAX==-1,"dispatch requires signed 32-bit conversion");',
           'extern void replay_fault(void);']
    expressions={}
    for call in calls:
        number=call['number'];root=call['root'];site=sites.get(number)
        if site is None or site['root']!=root:raise ValueError('dispatch site differs from captured call')
        if number in expressions:continue
        plan=plans[root];bound={}
        for provider in snapshot_providers(plan):
            if provider.get('binding_kind')!='root_argument':continue
            name=provider['argument'];function=provider['function'];index=provider['argument_index']
            if (name in bound or not IDENTIFIER.fullmatch(function) or type(index) is not int or
                not 0<=index<len(plan['arguments']) or plan['arguments'][index]['name']!=name or
                provider['return_type']!=plan['arguments'][index]['type']):
                raise ValueError('dispatch argument binding differs from plan')
            bound[name]='osrec_bound_'+function
        arguments=[]
        for index,argument in enumerate(plan['arguments']):
            if argument['name'] in bound:
                arguments.append(bound[argument['name']])
            elif argument['pointer'] or argument['type'] not in ('unsigned int','int'):
                raise ValueError('dispatch requires bound object pointers or 32-bit integer arguments')
            else:
                arguments.append('('+argument['type']+')osrec_argument(osrec_index,'+str(index)+')')
        result=RESULTS[site['return_kind']]
        signature=','.join(a['type'] for a in plan['arguments']) or 'void'
        lines.append('_Static_assert(__builtin_types_compatible_p(__typeof__(&'+root+'),'+result+' (*)('+signature+')),"dispatch function ABI differs");')
        invocation=root+'('+','.join(arguments)+')'
        expressions[number]=invocation+';return 0;' if result=='void' else 'return (uint32_t)'+invocation+';'
    lines += ['uint32_t osrec_invoke(uint32_t osrec_number){',
              ' static unsigned osrec_next;unsigned osrec_index=osrec_next++;',
              ' switch(osrec_index){']
    for index,call in enumerate(calls):
        lines.append(' case '+str(index)+':if(osrec_number!=UINT32_C('+str(call['number'])+'))break;'+expressions[call['number']])
    # Invalid routing must fault even when UINT32_MAX is a legitimate result.
    lines += [' default:break;}replay_fault();return 0;','}']
    return '\n'.join(lines)+'\n'
