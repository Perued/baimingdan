TARGET := iphone:clang:latest:14.0
INSTALL_TARGET_PROCESSES = com.dada.staff

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = QiangDanAuto
QiangDanAuto_FILES = Tweak.x
QiangDanAuto_CFLAGS = -fobjc-arc

include $(THEOS)/makefiles/tweak.mk
