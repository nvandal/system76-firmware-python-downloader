#!/usr/bin/python

import requests
import urllib3
import nacl.encoding
import nacl.signing
import struct
from base64 import b32encode,b32decode
from collections import namedtuple
import json
import hashlib
from datetime import datetime
import tarfile
import io

#Reference 
# https://github.com/pop-os/buildchain and
# https://github.com/pop-os/system76-firmware

#Config
#https://github.com/pop-os/system76-firmware/blob/master/src/config.rs
key = "GRD4KPGF2QUSBQVP3GR2VF5OVBXW3T4O6LZMR7YQJOYQ2MFHBKNA===="
url = "https://firmware.system76.com/buildchain/"
project = "firmware"
branch = "master"
ca_cert_file = "./system76.cert"

#Model specific
bios_model = "lemp9"
ec_project = "76ec"

def trunc_b32(b):
    return b32encode(b).decode("utf-8").rstrip("=")

#disable warning about subj alt name not existing
urllib3.disable_warnings(urllib3.exceptions.SubjectAltNameWarning)

#establish session with ca cert
with requests.Session() as s:
    s.verify = ca_cert_file 
    
    #retrive tail
    u = f'{url}tail/{project}/{branch}'
    #print(u)
    r = s.get(u)
    r.raise_for_status()
    tail = r.content
    
    #unpack signature and message
    signature,message = struct.unpack('@64s336s',tail)
    
    #unpack block
    public_key,previous_signature,counter,timestamp = struct.unpack('@32s64sqq',message[:112])
    
    #verify tail signature
    assert(b32decode(key) == public_key)
    vk = nacl.signing.VerifyKey(key,encoder=nacl.encoding.Base32Encoder)
    sm = nacl.signing.SignedMessage._from_parts(signature,message,tail)
    verified_message = vk.verify(sm)
    assert(verified_message == message)
    
    #unpack blockrequest
    BlockRequest= namedtuple('blockrequest', 'signature public_key previous_signature counter timestamp digest')
    request = BlockRequest._make(struct.unpack('@64s32s64sqq48s',message[112:]))
    
    #create unpadded b32 encoded block
    Block = namedtuple('block', 'signature public_key previous_signature counter timestamp digest')
    block = Block(trunc_b32(signature),trunc_b32(public_key),trunc_b32(previous_signature),counter,timestamp,trunc_b32(request.digest))
    
    #download manifest
    u = f'{url}object/{block.digest}'
    #print(u)
    r = s.get(u)
    r.raise_for_status()
    manifest_text = r.content

    #verify manifest digest
    manifest_hash = hashlib.sha384(manifest_text).digest()
    assert(trunc_b32(manifest_hash)==block.digest)
    
    #parse json
    manifest = json.loads(manifest_text)
    
    #get datestamp
    dt_object = datetime.fromtimestamp(manifest['time'])
    print(dt_object)
    
    #generate firmware data filename from firmware id
    project_hash = hashlib.sha256(ec_project.encode("utf-8")).hexdigest()
    filename = f'{bios_model}_{project_hash}.tar.xz'
    print(filename)
    
    #get firmware data digest
    digest = manifest['files'][filename]
    
    #download firmware data and save as file
    u = f'{url}object/{digest}'
    #print(u)
    r = s.get(u)
    r.raise_for_status()
    with open(filename, 'wb') as f:
        f.write(r.content)
    
    #verify firmware digest
    firmware_hash = hashlib.sha384(r.content).digest()
    assert(trunc_b32(firmware_hash)==digest)
    
    #extract changelog (from memory)
    with io.BytesIO(r.content) as file_like_object:
        with tarfile.open(fileobj=file_like_object, mode='r:xz') as tar:
            with tar.extractfile("./changelog.json") as f:
                changelog_text = f.read()
    
    #pretty print json
    changelog = json.loads(changelog_text)
    print(json.dumps(changelog,indent=2))


