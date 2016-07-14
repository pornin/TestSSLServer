#! /bin/sh

CSC=$(which mono-csc || which dmcs || echo "none")

if [ $CSC = "none" ]; then
	echo "Error: Please install mono-devel."
	exit 1
fi

$CSC /out:TestSSLServer.exe /main:TestSSLServer Src/*.cs Asn1/*.cs X500/*.cs
