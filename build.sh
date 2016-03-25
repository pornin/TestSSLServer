#! /bin/sh

CSC=$(which mono-csc || which dmcs)
$CSC /out:TestSSLServer.exe /main:TestSSLServer Src/*.cs Asn1/*.cs X500/*.cs
