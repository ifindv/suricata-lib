# script for suricata lib compile and install
# author: ifindv@gmail.com
# date: 2024-12-16
# usage:
#   ./build.sh          - build suricata only   
#   ./build.sh all      - build suricata and its dependencies
#   ./build.sh pack     - pack suricata libraries

# set cross compile flags
CROSS_PREFIX=
CROSS_FLAGS="CC=${CROSS_PREFIX}gcc"
CROSS_SYSROOT=
SYSROOT_FLAGS="--sysroot=$CROSS_SYSROOT"
CFLAGS="$CFLAGS -g -std=gnu99"

# set work directory

WORK_DIR=`pwd`
DEPS_DIR=$WORK_DIR/deps
INST_DIR=$WORK_DIR/build
PACK_DIR=$INST_DIR/pack

# set flag build all
build_all=0
if [ $# -eq 1 ]; then
    if [ $1 = "all" ]; then
        build_all=1
    fi
fi
if [ $build_all -eq 1 ]; then
    if [ -d $INST_DIR ]; then
        rm -rf $INST_DIR
    fi
    mkdir -p $INST_DIR
fi

# set flag build pack
build_pack=0
if [ $# -eq 1 ]; then
    if [ $1 = "pack" ]; then
        build_pack=1
    fi
fi

if [ $build_pack -eq 1 ]; then
    if [ -d $PACK_DIR ]; then
        rm -rf $PACK_DIR
    fi
    mkdir -p $PACK_DIR
    find build/ -name "*.so" | xargs -I {} cp {} build/pack/
    find build/ -name "*.a" | xargs -I {} cp {} build/pack/
    if [ -e suricata-lib.tgz ]; then
        rm -f suricata-lib.tgz
    fi
    tar -czvf suricata-lib.tgz -C build/pack .
    exit 0
fi

# download resources

# rm -fr $DEPS_DIR/*
# wget https://github.com/PCRE2Project/pcre2/releases/download/pcre2-10.42/pcre2-10.42.tar.gz -P $DEPS_DIR
# wget http://pyyaml.org/download/libyaml/yaml-0.2.5.tar.gz -P $DEPS_DIR
# wget https://codeload.github.com/akheron/jansson/zip/refs/heads/master -P $DEPS_DIR
# wget https://codeload.github.com/the-tcpdump-group/libpcap/zip/refs/heads/master -P $DEPS_DIR
# wget https://people.redhat.com/sgrubb/libcap-ng/libcap-ng-0.8.3.tar.gz -P $DEPS_DIR
# wget https://codeload.github.com/libunwind/libunwind/zip/refs/heads/master -P $DEPS_DIR
# wget https://astron.com/pub/file/file-5.45.tar.gz -P $DEPS_DIR
# wget http://security.ubuntu.com/ubuntu/pool/main/l/lz4/lz4_1.9.4.orig.tar.gz -P $DEPS_DIR
# wget https://static.rust-lang.org/dist/rust-1.74.0-x86_64-unknown-linux-gnu.tar.gz -P $DEPS_DIR

# install depends: pcre2

if [ $build_all -eq 1 ]; then
    if [ -d $INST_DIR/pcre2 ]; then
        rm -rf $INST_DIR/pcre2
    fi
    if [ -d $DEPS_DIR/pcre2-10.42 ]; then
        rm -rf $DEPS_DIR/pcre2-10.42
    fi
    mkdir -p $INST_DIR/pcre2

    cd $DEPS_DIR && tar zxvf pcre2-10.42.tar.gz && cd pcre2-10.42 && \
    ./configure $CROSS_FLAGS --prefix=$INST_DIR/pcre2 && make && make install
fi

LDFLAGS="$LDFLAGS -L$INST_DIR/pcre2/lib"
CFLAGS="$CFLAGS -I$INST_DIR/pcre2/include"

# install depends: yaml

if [ $build_all -eq 1 ]; then
    if [ -d $INST_DIR/yaml ]; then
        rm -rf $INST_DIR/yaml
    fi
    if [ -d $DEPS_DIR/yaml-0.2.5 ]; then
        rm -rf $DEPS_DIR/yaml-0.2.5
    fi
    mkdir -p $INST_DIR/yaml

    cd $DEPS_DIR && tar zxvf yaml-0.2.5.tar.gz && cd yaml-0.2.5 && \
    ./configure $CROSS_FLAGS --prefix=$INST_DIR/yaml && make && make install
fi

LDFLAGS="$LDFLAGS -L$INST_DIR/yaml/lib"
CFLAGS="$CFLAGS -I$INST_DIR/yaml/include"

# install depends: jansson

if [ $build_all -eq 1 ]; then
    if [ -d $INST_DIR/jansson ]; then
        rm -rf $INST_DIR/jansson
    fi
    if [ -d $DEPS_DIR/jansson-master ]; then
        rm -rf $DEPS_DIR/jansson-master
    fi
    mkdir -p $INST_DIR/jansson

    cd $DEPS_DIR && unzip jansson-master.zip && cd jansson-master && autoreconf -i && \
    ./configure $CROSS_FLAGS --prefix=$INST_DIR/jansson && make && make install
fi

LDFLAGS="$LDFLAGS -L$INST_DIR/jansson/lib"
CFLAGS="$CFLAGS -I$INST_DIR/jansson/include"

# install depends: libpcap

if [ $build_all -eq 1 ]; then
    if [ -d $INST_DIR/libpcap ]; then
        rm -rf $INST_DIR/libpcap
    fi
    if [ -d $DEPS_DIR/libpcap-master ]; then
        rm -rf $DEPS_DIR/libpcap-master
    fi
    mkdir -p $INST_DIR/libpcap

    cd $DEPS_DIR && unzip libpcap-master.zip && cd libpcap-master && autoreconf -i && \
    ./configure $CROSS_FLAGS --prefix=$INST_DIR/libpcap && make && make install
fi

LDFLAGS="$LDFLAGS -L$INST_DIR/libpcap/lib"
CFLAGS="$CFLAGS -I$INST_DIR/libpcap/include"

# install depends: libcap-ng

if [ $build_all -eq 1 ]; then
    if [ -d $INST_DIR/libcap-ng ]; then
        rm -rf $INST_DIR/libcap-ng
    fi
    if [ -d $DEPS_DIR/libcap-ng-0.8.3 ]; then
        rm -rf $DEPS_DIR/libcap-ng-0.8.3
    fi
    mkdir -p $INST_DIR/libcap-ng

    cd $DEPS_DIR && tar zxvf libcap-ng-0.8.3.tar.gz && cd libcap-ng-0.8.3 && \
    ./configure $CROSS_FLAGS --prefix=$INST_DIR/libcap-ng && make && make install
fi

LDFLAGS="$LDFLAGS -L$INST_DIR/libcap-ng/lib"
CFLAGS="$CFLAGS -I$INST_DIR/libcap-ng/include"

# install depends: libunwind

if [ $build_all -eq 1 ]; then
    if [ -d $INST_DIR/libunwind ]; then
        rm -rf $INST_DIR/libunwind
    fi
    if [ -d $DEPS_DIR/libunwind-master ]; then
        rm -rf $DEPS_DIR/libunwind-master
    fi
    mkdir -p $INST_DIR/libunwind

    cd $DEPS_DIR && unzip libunwind-master.zip && cd libunwind-master && autoreconf -i && \
    ./configure $CROSS_FLAGS --prefix=$INST_DIR/libunwind && make && make install
fi

LDFLAGS="$LDFLAGS -L$INST_DIR/libunwind/lib"
CFLAGS="$CFLAGS -I$INST_DIR/libunwind/include"

# install depends: magic

# if [ $build_all -eq 1 ]; then
#     if [ -d $INST_DIR/magic ]; then
#         rm -rf $INST_DIR/magic
#     fi
#     if [ -d $DEPS_DIR/file-5.45 ]; then
#         rm -rf $DEPS_DIR/file-5.45
#     fi
#     mkdir -p $INST_DIR/magic

#     cd $DEPS_DIR && tar zxvf file-5.45.tar.gz && cd file-5.45 &&  \
#     ./configure $CROSS_FLAGS --prefix=$INST_DIR/magic && make && make install 
#     # cd $DEPS_DIR && cd file-5.45 && /bin/sh libtool --mode=execute ./src/file -C -m magic
# fi

# LDFLAGS="$LDFLAGS -L$INST_DIR/magic/lib"
# CFLAGS="$CFLAGS -I$INST_DIR/magic/include"

# install depends: lz4

if [ $build_all -eq 1 ]; then
    if [ -d $INST_DIR/lz4 ]; then
        rm -rf $INST_DIR/lz4
    fi
    if [ -d $DEPS_DIR/lz4-1.9.4 ]; then
        rm -rf $DEPS_DIR/lz4_1.9.4
    fi
    mkdir -p $INST_DIR/lz4

    cd $DEPS_DIR && tar zxvf lz4_1.9.4.orig.tar.gz && cd lz4-1.9.4 && \
    make $CROSS_FLAGS && make install PREFIX=$INST_DIR/lz4
fi

LDFLAGS="$LDFLAGS -L$INST_DIR/lz4/lib"
CFLAGS="$CFLAGS -I$INST_DIR/lz4/include"

# install depends: rust

if [ $build_all -eq 1 ]; then
    if [ ! -e $DEPS_DIR/rust-1.74.0-x86_64-unknown-linux-gnu.tar.gz ]; then
        wget https://static.rust-lang.org/dist/rust-1.74.0-x86_64-unknown-linux-gnu.tar.gz -P $DEPS_DIR
    fi
    if [ -d $INST_DIR/rust ]; then
        rm -rf $INST_DIR/rust
    fi
    if [ -d $DEPS_DIR/rust-1.74.0-x86_64-unknown-linux-gnu ]; then
        rm -rf $DEPS_DIR/rust-1.74.0-x86_64-unknown-linux-gnu
    fi
    mkdir -p $INST_DIR/rust

    cd $DEPS_DIR && tar xvf rust-1.74.0-x86_64-unknown-linux-gnu.tar.gz && cd rust-1.74.0-x86_64-unknown-linux-gnu && \ 
    ./install.sh --prefix=$INST_DIR/rust
fi

LDFLAGS="$LDFLAGS -L$INST_DIR/rust/lib"

# install suricata

if [ -d $INST_DIR/suricata ]; then
    rm -rf $INST_DIR/suricata
fi
mkdir -p $INST_DIR/suricata
mkdir -p $INST_DIR/suricata/etc
mkdir -p $INST_DIR/suricata/var

# FIXME:
#   1. configure: force standard gnu99, cause CFLAGS not work
#   2. suricata-lib.Po: cannot generated by automake, use a backup file
#   3. libmagic: disabled cause compile error

export PATH=$INST_DIR/rust/bin:$PATH

cd $WORK_DIR && aclocal -I m4 && automake --add-missing && cp configure.bak configure && chmod 777 configure
cd $WORK_DIR && chmod 777 libhtp/*.sh
cd $WORK_DIR && ./configure $CROSS_FLAGS --disable-gccmarch-native --prefix=$INST_DIR/suricata --sysconfdir=/opt/suricata/etc --localstatedir=/opt/suricata/var \
    --enable-libmagic=false --enable-debug \
    LDFLAGS="$LDFLAGS" CFLAGS="$CFLAGS" PATH="$INST_DIR/rust/bin:$PATH"

cd $WORK_DIR && cp suricata-lib.Po.bak src/.deps/suricata-lib.Po
cd $WORK_DIR && make && make install && make install-library && cp src/suricata-lib.h $INST_DIR/suricata/include
