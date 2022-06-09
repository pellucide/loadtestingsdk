#add the path for mingw gcc
#export PATH=/d/TDM-GCC-64/bin:$PATH
export PATH=/mingw32/bin:$PATH
LIBSODIUM_MSVC=libsodium-1.0.18-msvc/libsodium/
LIBSODIUM_MINGW_WIN32=libsodium-1.0.18-mingw/libsodium-win32
LIBOPENSSL11=./openssl-1.1/
LIBOPENSSL3=./openssl-3/x86/

rm -f transmitlib.o
gcc -m32 -I $LIBOPENSSL3/include -I $LIBSODIUM_MINGW_WIN32/include/ -c transmitlib.c 

#rm EVP_PKEY_RSA_keygen.o 
#gcc -m32 -I $LIBOPENSSL3/include -c EVP_PKEY_RSA_keygen.c 


  #-L$LIBSODIUM_MSVC/Win32/Release/v142/dynamic/ \
  #-L$LIBSODIUM_MSVC/Win32/Release/v142/static/ \
  #-L$LIBOPENSSL/lib \


rm -f transmitlib.dll
gcc  -m32 \
  -I $LIBOPENSSL3/include \
  -L $LIBOPENSSL3/bin \
  -L$LIBSODIUM_MINGW_WIN32/bin \
  -L$LIBSODIUM_MINGW_WIN32/lib \
  --shared  transmitlib.o  -o transmitlib.dll -lsodium -lcrypto-3

