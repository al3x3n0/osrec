#include "graph_types.h"
static Node nodes[3];
static Node *head,*tail;
static uint64_t calls;
static void append(uint64_t value)
{
    Node *node=NULL;
    for(unsigned i=0;i<3;++i)if(!nodes[i].live){node=&nodes[i];break;}
    if(!node)return;
    node->live=1;++node->generation;node->value=value;
    if(!head){head=tail=node;node->next=NULL;}
    else{tail->next=node;node->next=head;tail=node;}
}
static void release_head(void)
{
    Node *old=head;
    if(head==tail){head=tail=NULL;}
    else{head=old->next;tail->next=head==tail ? NULL : head;}
    old->live=0;old->value=0;old->next=NULL;
}
uint64_t GraphStep(uint64_t operation,uint64_t value,void *output)
{
    if(operation==1)append(value);
    else if(operation==2)head->value+=value;
    else if(operation==3)release_head();
    else if(operation==4){Node *old=head;head=head->next;tail=old;}
    ++calls;
    uint64_t result=head ? head->value : 0;
    for(unsigned i=0;i<8;++i)((unsigned char *)output)[i]=(unsigned char)(result>>(8*i));
    return result;
}
