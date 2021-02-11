# Handles a tiny bit of extra work so that we don't break when doing a
# DPDK make like what rte.app.mk would do

# Taken from Intel DPDK to put -Wl, before a -melf option otherwise this breaks
# We also need to put -Wl in front of libaries to stop libtool reordering them
ifeq ($(LINK_USING_CC),1)
comma := ,
LDFLAGS := $(addprefix -Wl$(comma),$(LDFLAGS))
endif

# Ensure extra libraries are linked in
ifeq ($(CONFIG_RTE_LIBC),y)
DPDKLIBS += -Wl,-lc -Wl,-lm
endif

ifeq ($(CONFIG_RTE_LIBRTE_MLX4_PMD), y)
DPDKLIBS += -Wl,-libverbs -Wl,-lmlx4 -Wl,-ldl
endif
ifeq ($(CONFIG_RTE_LIBRTE_MLX5_PMD), y)
DPDKLIBS += -Wl,-libverbs -Wl,-lmlx5 -Wl,-ldl
endif

DPDKLIBS += $(addprefix -Wl$(comma),$(EXECENV_LDLIBS))
DPDKLIBS += $(addprefix -Wl$(comma),$(CPU_LDLIBS))
