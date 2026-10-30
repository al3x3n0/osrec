/* A selected-task queue projection, not a complete native Linux runqueue.
 * Accounting, utilization, core scheduling and migration effects are not replayed.
 * Boundary checks make that restriction explicit and verify callback ordering.
 */
#define ENQUEUE_WAKEUP 0x01
#define ENQUEUE_RESTORE 0x02
#define ENQUEUE_NOCLOCK 0x08
#define ENQUEUE_MIGRATED 0x40
#define DEQUEUE_SLEEP 0x01
#define DEQUEUE_SAVE 0x02
#define DEQUEUE_NOCLOCK 0x08
#define TASK_ON_RQ_QUEUED 1
#define TASK_ON_RQ_MIGRATING 2
struct rq {struct task_struct *queued;unsigned nr_running;};
static struct rq projected_rq={&selected,1};
static unsigned queue_operation,queue_flags,hook_step,queue_witness_count;
struct queue_witness {uint32_t kind,flags,state,on_rq,on_cpu,nr_running,queued_tid,step;};
_Static_assert(sizeof(struct queue_witness)==32,"queue witness layout");
struct queue_witness osrec_linux_irq_queue[4];
static void queue_snapshot(unsigned kind)
{
    check(queue_witness_count<4);
    osrec_linux_irq_queue[queue_witness_count++]=(struct queue_witness){
        kind,queue_flags,selected.__state,selected.on_rq,selected.on_cpu,
        projected_rq.nr_running,projected_rq.queued?projected_rq.queued->id:0,hook_step};
}
static void queue_hook(struct rq *rq,struct task_struct *p,unsigned operation,unsigned step)
{
    check(rq==&projected_rq && p==&selected && queue_operation==operation && hook_step==step);
    ++hook_step;
}
static void sched_info_enqueue(struct rq *rq,struct task_struct *p){queue_hook(rq,p,2,0);}
static void psi_enqueue(struct task_struct *p,int wakeup){check(wakeup==1);queue_hook(&projected_rq,p,2,1);}
static void uclamp_rq_inc(struct rq *rq,struct task_struct *p){queue_hook(rq,p,2,2);}
static void sched_info_dequeue(struct rq *rq,struct task_struct *p){queue_hook(rq,p,1,2);}
static void psi_dequeue(struct task_struct *p,int sleep){check(sleep==1);queue_hook(&projected_rq,p,1,3);}
static void uclamp_rq_dec(struct rq *rq,struct task_struct *p){queue_hook(rq,p,1,4);}
static int sched_core_enabled(struct rq *rq)
{
    check(queue_operation==1 || queue_operation==2);
    queue_hook(rq,&selected,queue_operation,queue_operation==1?1:4);return 0;
}
static void update_rq_clock(struct rq *rq){(void)rq;finish(1);}
static void sched_core_enqueue(struct rq *rq,struct task_struct *p){(void)rq;(void)p;finish(1);}
static void sched_core_dequeue(struct rq *rq,struct task_struct *p){(void)rq;(void)p;finish(1);}
static void sched_mm_cid_migrate_to(struct rq *rq,struct task_struct *p){(void)rq;(void)p;finish(1);}
static int task_on_rq_migrating(struct task_struct *p){return READ_ONCE(p->on_rq)==TASK_ON_RQ_MIGRATING;}
static void on_rq_writer(uint32_t *field)
{
    check(field==&selected.on_rq);
    if(queue_operation==1){
        check(!selected.on_rq && selected.on_cpu && current==1 && !irq_depth);
        queue_hook(&projected_rq,&selected,1,0);queue_snapshot(1);
    }else{
        check(queue_operation==2 && selected.on_rq==1 && !selected.on_cpu && irq_depth==1);
        queue_hook(&projected_rq,&selected,2,5);queue_snapshot(4);
    }
}
#define ASSERT_EXCLUSIVE_WRITER(field) on_rq_writer(&(field))
static void class_enqueue(struct rq *rq,struct task_struct *p,int flags)
{
    check(flags==(ENQUEUE_WAKEUP|ENQUEUE_NOCLOCK) && !rq->queued && !rq->nr_running &&
          !p->on_rq && !p->on_cpu && p->__state==checkpoint_activation_state);
    queue_hook(rq,p,2,3);rq->queued=p;rq->nr_running=1;++activation_count;queue_snapshot(3);
}
static void class_dequeue(struct rq *rq,struct task_struct *p,int flags)
{
    check(flags==(DEQUEUE_SLEEP|DEQUEUE_NOCLOCK) && rq->queued==p && rq->nr_running==1 &&
          !p->on_rq && p->on_cpu && p->__state==checkpoint_sleep_state);
    emit_task_state(1);queue_hook(rq,p,1,5);rq->queued=NULL;rq->nr_running=0;queue_snapshot(2);
}
static const struct sched_class projected_class={class_enqueue,class_dequeue};
#include "sched_queue.c"
static void projected_activate(struct task_struct *p)
{
    check(!queue_operation);queue_operation=2;hook_step=0;queue_flags=ENQUEUE_WAKEUP|ENQUEUE_NOCLOCK;
    emit_task_state(3);activate_task(&projected_rq,p,(int)queue_flags);
    check(hook_step==6 && projected_rq.queued==p && p->on_rq==1);queue_operation=0;
}
static void projected_deactivate(struct task_struct *p)
{
    check(!queue_operation);queue_operation=1;hook_step=0;queue_flags=DEQUEUE_SLEEP|DEQUEUE_NOCLOCK;
    deactivate_task(&projected_rq,p,(int)queue_flags);
    check(hook_step==6 && !projected_rq.queued && !p->on_rq);queue_operation=0;
}
