TARGET := iphone:clang:latest:14.0
INSTALL_TARGET_PROCESSES = com.dada.staff

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = baimingdan
baimingdan_FILES = Tweak.x
baimingdan_CFLAGS = -fobjc-arc

include $(THEOS)/makefiles/tweak.mk
