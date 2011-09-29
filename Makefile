# (C)2004-2010 SourceMod Development Team
# Makefile written by David "BAILOPAN" Anderson

SMSDK = ../../sourcemod-1.3
HL2SDK_ORIG = ../../hl2sdks/hl2sdk
HL2SDK_OB = ../../hl2sdks/hl2sdk-ob
HL2SDK_OB_VALVE = ../../hl2sdks/hl2sdk-ob-valve
HL2SDK_L4D = ../../hl2sdks/hl2sdk-l4d
HL2SDK_L4D2 = ../../hl2sdks/hl2sdk-l4d2

PROJECT = smrcon

OBJECTS = sdk/smsdk_ext.cpp extension.cpp rcon.cpp CDetour/detours.cpp asm/asm.c

C_OPT_FLAGS = -DNDEBUG -O3 -funroll-loops -pipe -fno-strict-aliasing
C_DEBUG_FLAGS = -D_DEBUG -DDEBUG -g -ggdb3
C_GCC4_FLAGS = -fvisibility=hidden
CPP_GCC4_FLAGS = -fvisibility-inlines-hidden
CPP = /opt/crosstool/gcc-3.4.1-glibc-2.3.2/i686-unknown-linux-gnu/bin/i686-unknown-linux-gnu-gcc

##########################
### SDK CONFIGURATIONS ###
##########################

override ENGSET = false

# Check for valid list of engines
ifneq (,$(filter original orangebox orangeboxvalve left4dead left4dead2,$(ENGINE)))
	override ENGSET = true
endif

ifeq "$(ENGINE)" "original"
	HL2SDK = $(HL2SDK_ORIG)
	CFLAGS += -DSOURCE_ENGINE=1
	BINADD = .1.ep1
endif
ifeq "$(ENGINE)" "orangebox"
	HL2SDK = $(HL2SDK_OB)
	CFLAGS += -DSOURCE_ENGINE=3
	BINADD = .2.ep2
endif
ifeq "$(ENGINE)" "orangeboxvalve"
	HL2SDK = $(HL2SDK_OB_VALVE)
	CFLAGS += -DSOURCE_ENGINE=6
	BINADD = .2.ep2v
endif
ifeq "$(ENGINE)" "left4dead"
	HL2SDK = $(HL2SDK_L4D)
	CFLAGS += -DSOURCE_ENGINE=7
	BINADD = .2.l4d
endif
ifeq "$(ENGINE)" "left4dead2"
	HL2SDK = $(HL2SDK_L4D2)
	CFLAGS += -DSOURCE_ENGINE=8
	BINADD = .2.l4d2
endif

HL2PUB = $(HL2SDK)/public

OS := $(shell uname -s)

ifeq "$(OS)" "Darwin"
	LIB_EXT = dylib
	HL2LIB = $(HL2SDK)/lib/mac
else
	LIB_EXT = so
	ifeq "$(ENGINE)" "original"
		HL2LIB = $(HL2SDK)/linux_sdk
	else
		HL2LIB = $(HL2SDK)/lib/linux
	endif
endif

# if ENGINE is original or OB
ifneq (,$(filter original orangebox,$(ENGINE)))
	LIB_SUFFIX = _i486.$(LIB_EXT)
else
	LIB_PREFIX = lib
	LIB_SUFFIX = .$(LIB_EXT)
endif

INCLUDE += -I. -I.. -Isdk -I$(SMSDK)/public -I$(SMSDK)/public/sourcepawn \
	-I$(HL2PUB) -I$(HL2PUB)/tier0 -I$(HL2PUB)/tier1

LINK_HL2 = $(HL2LIB)/tier1_i486.a $(LIB_PREFIX)vstdlib$(LIB_SUFFIX) $(LIB_PREFIX)tier0$(LIB_SUFFIX)

LINK += $(LINK_HL2)

CFLAGS += -DSE_EPISODEONE=1 -DSE_DARKMESSIAH=2 -DSE_ORANGEBOX=3 -DSE_BLOODYGOODTIME=4 -DSE_EYE=5 \
	-DSE_ORANGEBOXVALVE=6 -DSE_LEFT4DEAD=7 -DSE_LEFT4DEAD2=8 -DSE_ALIENSWARM=9

LINK += -m32 -lm -ldl

CFLAGS += -Dstricmp=strcasecmp -D_stricmp=strcasecmp -D_strnicmp=strncasecmp -Dstrnicmp=strncasecmp \
	-D_snprintf=snprintf -D_vsnprintf=vsnprintf -D_alloca=alloca -Dstrcmpi=strcasecmp -Wall -Werror \
	-Wno-switch -Wno-unused -mfpmath=sse -msse -DSOURCEMOD_BUILD -DHAVE_STDINT_H -m32
CPPFLAGS += -Wno-non-virtual-dtor -fno-exceptions -fno-rtti

BINARY = $(PROJECT).ext$(BINADD).$(LIB_EXT)

ifeq "$(DEBUG)" "true"
	BIN_DIR = Debug
	CFLAGS += $(C_DEBUG_FLAGS)
else
	BIN_DIR = Release
	CFLAGS += $(C_OPT_FLAGS)
endif

BIN_DIR := $(BIN_DIR).$(ENGINE)

ifeq "$(OS)" "Darwin"
	LIB_EXT = dylib
	CFLAGS += -isysroot /Developer/SDKs/MacOSX10.5.sdk
	LINK += -dynamiclib -lstdc++ -mmacosx-version-min=10.5
else
	LIB_EXT = so
	CFLAGS += -D_LINUX
	LINK += -shared
endif

GCC_VERSION := $(shell $(CPP) -dumpversion >&1 | cut -b1)
ifeq "$(GCC_VERSION)" "4"
	CFLAGS += $(C_GCC4_FLAGS)
	CPPFLAGS += $(CPP_GCC4_FLAGS)
endif

OBJ_BIN := $(OBJECTS:%.cpp=$(BIN_DIR)/%.o)

$(BIN_DIR)/%.o: %.cpp
	$(CPP) $(INCLUDE) $(CFLAGS) $(CPPFLAGS) -o $@ -c $<

all: check
	mkdir -p $(BIN_DIR)/sdk
	mkdir -p $(BIN_DIR)/CDetour
	ln -sf $(HL2LIB)/$(LIB_PREFIX)vstdlib$(LIB_SUFFIX)
	ln -sf $(HL2LIB)/$(LIB_PREFIX)tier0$(LIB_SUFFIX)
	$(MAKE) -f Makefile extension

check:
	if [ "$(ENGSET)" = "false" ]; then \
		echo "You must supply one of the following values for ENGINE:"; \
		echo "left4dead2, left4dead, orangeboxvalve, orangebox, or original"; \
		exit 1; \
	fi

extension: check $(OBJ_BIN)
	$(CPP) $(INCLUDE) $(OBJ_BIN) $(LINK) -o $(BIN_DIR)/$(BINARY)

debug:
	$(MAKE) -f Makefile all DEBUG=true

default: all

clean: check
	rm -rf $(BIN_DIR)/*.o
	rm -rf $(BIN_DIR)/sdk/*.o
	rm -rf $(BIN_DIR)/$(BINARY)

