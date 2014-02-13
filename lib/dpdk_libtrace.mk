# Handles a tiny bit of extra work so that we don't break when doing a
# DPDK make like what rte.app.mk would do

# Taken from Intel DPDK to put -Wl, before a -melf option otherwise this breaks
ifeq ($(LINK_USING_CC),1)
comma := ,
LDFLAGS := $(addprefix -Wl$(comma),$(LDFLAGS))
endif

# Ensure extra libraries are linked in
ifeq ($(CONFIG_RTE_LIBC),y)
DPDKLIBS += -lc
DPDKLIBS += -lm
endif

DPDKLIBS += $(EXECENV_LDLIBS)
DPDKLIBS += $(CPU_LDLIBS)
