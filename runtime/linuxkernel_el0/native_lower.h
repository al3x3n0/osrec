#ifndef LK_NATIVE_LOWER_H
#define LK_NATIVE_LOWER_H
struct lk_native_lower {
    const uint64_t (*ranges)[2];
    uint64_t count, base, veneers;
    const uint64_t *origins;
};
__attribute__((visibility("hidden")))
const struct lk_native_lower *lk_native_lowering(void);
__attribute__((visibility("hidden")))
int lk_native_user_access(struct osrec_shadow *,struct osrec_context *,uint32_t,uint64_t,unsigned);
#define osrec_kernel_ranges (lk_native_lowering()->ranges)
#define osrec_kernel_range_count (lk_native_lowering()->count)
#define osrec_veneer_base (lk_native_lowering()->base)
#define osrec_veneer_count (lk_native_lowering()->veneers)
#define osrec_veneer_origins (lk_native_lowering()->origins)
#endif
