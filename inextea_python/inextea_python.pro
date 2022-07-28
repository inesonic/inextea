##-*-makefile-*-########################################################################################################
# Copyright 2021 - 2022 Inesonic, LLC
#
# MIT License:
#   Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
#   documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
#   rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
#   permit persons to whom the Software is furnished to do so, subject to the following conditions:
#   
#   The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
#   Software.
#   
#   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
#   WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS
#   OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
#   OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
########################################################################################################################

########################################################################################################################
# Basic build characteristics
#

TEMPLATE = lib

CONFIG -= qt
CONFIG += shared c++14 no_plugin_name_prefix plugin

########################################################################################################################
# Source files:
#

SOURCES = inextea_python.cpp

########################################################################################################################
# Python
#

exists(/usr/include/python3.8/Python.h) {
    INCLUDEPATH += /usr/include/python3.8/
} else {
    exists(/usr/include/python3.9/Python.h) {
        INCLUDEPATH += /usr/include/python3.9/
    } else {
        exists(/usr/include/python3.10/Python.h) {
            INCLUDEPATH += /usr/include/python3.10/
        } else {
            error("Could not find Python.h")
        }
    }
}

########################################################################################################################
# Libraries
#

INEXTEA_BASE = $${OUT_PWD}/../inextea
INCLUDEPATH += $${PWD}/../inextea/include

unix {
    CONFIG(debug, debug|release) {
        LIBS += -L$${INEXTEA_BASE}/build/debug/ -linextea
        PRE_TARGETDEPS += $${INEXTEA_BASE}/build/debug/libinextea.a
    } else {
        LIBS += -L$${INEXTEA_BASE}/build/release/ -linextea
        PRE_TARGETDEPS += $${INEXTEA_BASE}/build/release/libinextea.a
    }
}

win32 {
    CONFIG(debug, debug|release) {
        LIBS += $${INEXTEA_BASE}/build/Debug/inextea.lib
        PRE_TARGETDEPS += $${INEXTEA_BASE}/build/Debug/inextea.lib
    } else {
        LIBS += $${INEXTEA_BASE}/build/Release/inextea.lib
        PRE_TARGETDEPS += $${INEXTEA_BASE}/build/Release/inextea.lib
    }
}

########################################################################################################################
# Locate build intermediate and output products
#

CONFIG(debug, debug|release) {
    unix:DESTDIR = build/debug
    win32:DESTDIR = build/Debug
} else {
    unix:DESTDIR = build/release
    win32:DESTDIR = build/Release
}

TARGET = inextea

OBJECTS_DIR = $${DESTDIR}/objects
MOC_DIR = $${DESTDIR}/moc
RCC_DIR = $${DESTDIR}/rcc
UI_DIR = $${DESTDIR}/ui
