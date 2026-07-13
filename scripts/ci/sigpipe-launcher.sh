#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# CTest test launcher that runs each test with SIGPIPE ignored.
#
# Some integration tests write to a loopback socket after the peer has closed
# it (a benign teardown race); with the default SIGPIPE disposition that kills
# the process. ctest resets SIGPIPE to its default for the test processes it
# spawns, so ignoring it in the parent shell does not reach the tests. This
# launcher restores SIG_IGN and then execs the test, and an ignored signal
# disposition IS inherited across exec -- so the test sees EPIPE from write()
# instead of dying. Wired in via -DCMAKE_CROSSCOMPILING_EMULATOR so it applies
# to every test with no change to library or test source, and works uniformly
# for plain, ASan and TSAN builds (unlike an LD_PRELOAD shim, which collides
# with the sanitizer runtime ordering).
trap '' PIPE
exec "$@"
