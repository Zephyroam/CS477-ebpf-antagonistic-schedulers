NEST_ST(WAKEUP_ATTACHED, STAT_GRP_WAKEUP, "Attached CPU was idle, and in primary nest")
NEST_ST(WAKEUP_PREV_PRIMARY, STAT_GRP_WAKEUP, "Previous CPU was idle, and in primary nest")
NEST_ST(WAKEUP_FULLY_IDLE_PRIMARY, STAT_GRP_WAKEUP, "Woken up to fully idle primary nest core")
NEST_ST(WAKEUP_ANY_IDLE_PRIMARY, STAT_GRP_WAKEUP, "Woken up to idle logical primary nest core")
NEST_ST(WAKEUP_FULLY_IDLE_RESERVE, STAT_GRP_WAKEUP, "Woken up to fully idle reserve nest core")
NEST_ST(WAKEUP_ANY_IDLE_RESERVE, STAT_GRP_WAKEUP, "Woken up to idle logical reserve nest core")
NEST_ST(WAKEUP_IDLE_OTHER, STAT_GRP_WAKEUP, "Woken to any idle logical core in p->cpus_ptr")

NEST_ST(PROMOTED_TO_PRIMARY, STAT_GRP_NEST, "A core was promoted into the primary nest")
NEST_ST(PROMOTED_TO_RESERVED, STAT_GRP_NEST, "A core was promoted into the reserve nest")
NEST_ST(DEMOTED_TO_RESERVED, STAT_GRP_NEST, "A core was demoted into the reserve nest")
NEST_ST(RESERVED_AT_CAPACITY, STAT_GRP_NEST, "Reserved nest was at capacity")
NEST_ST(SCHEDULED_COMPACTION, STAT_GRP_NEST, "Scheduled a primary core to be compacted")
NEST_ST(CANCELLED_COMPACTION, STAT_GRP_NEST, "Cancelled a primary core from being compacted at task wakeup time")
NEST_ST(EAGERLY_COMPACTED, STAT_GRP_NEST, "A core was compacted in ops.dispatch()")
NEST_ST(CALLBACK_COMPACTED, STAT_GRP_NEST, "A core was compacted in the scheduled timer callback")

NEST_ST(CONSUMED, STAT_GRP_CONSUME, "A task was consumed from the global DSQ")
NEST_ST(NOT_CONSUMED, STAT_GRP_CONSUME, "There was no task in the global DSQ")