/* Bounded replay model, not Linux's red-black tree implementation. */
#ifndef OSREC_ORDERED_TIMER_QUEUE_H
#define OSREC_ORDERED_TIMER_QUEUE_H
#include <stdint.h>
#include <stddef.h>
struct timerqueue_node {uint64_t expires;unsigned id,queued;};
struct timerqueue_head {struct timerqueue_node *nodes[2];unsigned count;};
static void ordered_validate(const struct timerqueue_head *head)
{
    check(head && head->count<=2);
    for(unsigned i=0;i<2;++i){
        if(i>=head->count){check(head->nodes[i]==NULL);continue;}
        check(head->nodes[i] && head->nodes[i]->queued==1 && head->nodes[i]->id);
        if(i)check(head->nodes[i]!=head->nodes[i-1] && head->nodes[i]->id!=head->nodes[i-1]->id &&
                   head->nodes[i-1]->expires<=head->nodes[i]->expires);
    }
}
static struct timerqueue_node *ordered_first(const struct timerqueue_head *head)
{ordered_validate(head);return head->count?head->nodes[0]:NULL;}
static int ordered_insert(struct timerqueue_head *head,struct timerqueue_node *node)
{
    ordered_validate(head);check(node && node->id && !node->queued && head->count<2);
    unsigned at=0;
    while(at<head->count){check(head->nodes[at]!=node && head->nodes[at]->id!=node->id);++at;}
    at=0;while(at<head->count && head->nodes[at]->expires<=node->expires)++at;
    for(unsigned i=head->count;i>at;--i)head->nodes[i]=head->nodes[i-1];
    head->nodes[at]=node;++head->count;node->queued=1;ordered_validate(head);
    return ordered_first(head)==node;
}
static int ordered_remove(struct timerqueue_head *head,struct timerqueue_node *node)
{
    ordered_validate(head);check(node && node->queued);
    unsigned at=0;while(at<head->count && head->nodes[at]!=node)++at;
    check(at<head->count);
    for(unsigned i=at+1;i<head->count;++i)head->nodes[i-1]=head->nodes[i];
    --head->count;check(head->count<2);
    head->nodes[head->count]=NULL;node->queued=0;ordered_validate(head);
    return head->count!=0;
}
#endif
