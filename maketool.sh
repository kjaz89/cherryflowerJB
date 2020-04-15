#!/bin/sh

#git submodule init
#git submodule update

mkdir cherryflower

cd cherryflower/
mkdir src/
cp -a ../src/Cydia6.tar src/Cydia6.tar
cd ../

cd cherry/
mkdir build
cd build/
cmake ../xpwn
make ipsw
cp -a ipsw-patch/ipsw ../../cherryflower/cherry
cd ../../

cd idevice/iPwnder32/
gcc -lusb-1.0 -lcrypto -I./ -o pwnedDFU exploit.c usb.c payload_gen.c
cp -a pwnedDFU ../../cherryflower/pwnedDFU
cd ../../

cd ios/
cd kernel/sbpwn6/
gcc -isysroot /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS6.1.sdk -arch armv7 sbpwn6.c patchfinder.c sb_evaluate_hook.s sb_evaluate_trampoline.s -o sbpwn6
ldid -Stfp0.xml sbpwn6
cp -a sbpwn6 ../../../src/untether6/.untether6dra
cd ../../../src/untether6/
tar -cvf untether6.tar .untether6dra private/
mv -v untether6.tar ..
cd ../../
cp -a src/untether6.tar cherryflower/src/untether6.tar


