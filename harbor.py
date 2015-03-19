#!/usr/bin/python
import os
import sys
import json
import time
import shutil
import socket
import random
import filecmp
import requests
import argparse
import subprocess
import ConfigParser
from string import Template
from datetime import date

parser = argparse.ArgumentParser()
parser.add_argument('action', help='action can be one of: build rebase mac run stop enter rm')
parser.add_argument('containers', nargs='*')
parser.add_argument('--flatten', '-f', action='store_true', help='Combine filesystem layers created in the build process to save space')
parser.add_argument('--config', '-c', help='Set the config file', default='/usr/csee/etc/docker.conf')
args = parser.parse_args()

config = ConfigParser.ConfigParser()
config.read(args.config)

RUN_FLAGS = config.get('main', 'run_flags')

host = socket.gethostname()
if not os.path.isfile("/var/lib/puppet/ssl/combined.pem"):
  os.system('bash -c "cat /var/lib/puppet/ssl/private_keys/{host}.pem /var/lib/puppet/ssl/certs/{host}.pem > /var/lib/puppet/ssl/combined.pem"'.format(host=host))

def get(path):
  r = requests.get('https://foreman.cs.umbc.edu:8140'+path,
    verify="/var/lib/puppet/ssl/certs/ca.pem",
    cert="/var/lib/puppet/ssl/combined.pem"
  )
  return r

def put(path, data):
  r = requests.put('https://foreman.cs.umbc.edu:8140'+path,
    verify="/var/lib/puppet/ssl/certs/ca.pem",
    cert="/var/lib/puppet/ssl/combined.pem"
  )
  return r

def delete(path):
  r = requests.delete('https://foreman.cs.umbc.edu:8140'+path,
    verify="/var/lib/puppet/ssl/certs/ca.pem",
    cert="/var/lib/puppet/ssl/combined.pem"
  )
  return r

if args.action == 'build':
  for i in args.containers:
    if i == 'base':
      print "Currently unable to build base"
      continue
    builddir = os.path.join(config.get('main', 'dockerfilepath'), i)
    if not(os.path.isdir(builddir)):
      os.mkdir(builddir)
    for j in os.listdir(config.get('main', 'commonfilesdir')):
      if os.path.exists(os.path.join(builddir, j)):
        if not filecmp.cmp(os.path.join(config.get('main', 'commonfilesdir'), j), os.path.join(builddir, j)):
          shutil.copyfile(os.path.join(config.get('main', 'commonfilesdir'), j), os.path.join(builddir, j))
      else:
        shutil.copyfile(os.path.join(config.get('main', 'commonfilesdir'), j), os.path.join(builddir, j))

    if not os.system('docker build -t csee/{i}:latest ./{i}/'.format(i=i)):
      try:
        data = json.loads(get("/production/certificate_status/{i}-build.cs.umbc.edu".format(i=i)).text)
        if data['state'] == "signed":
          print "Cert already signed, deleting"
          delete("/production/certificate_status/{i}-build.cs.umbc.edu".format(i=i))
        elif data['state'] == "requested":
          print "Cert has already been requested, deleting"
          delete("/production/certificate_status/{i}-build.cs.umbc.edu".format(i=i))
        else:
          print "Unknown cert state:", data['state']
      except:
        print "Failed to get puppet cert information. Node may not exist yet."
      os.system('docker run -t -i '+RUN_FLAGS+' --name {i}-build.cs.umbc.edu -h {i}-build.cs.umbc.edu csee/{i}:latest /usr/sbin/init'.format(i=i))
      if args.flatten:
        os.system('docker export {i}-build.cs.umbc.edu | docker import - csee/{i}:latest'.format(i=i))
      else:
        os.system('docker commit {i}-build.cs.umbc.edu csee/{i}:latest'.format(i=i))
      os.system('docker rm {i}-build.cs.umbc.edu'.format(i=i))

if args.action == 'rebase':
  if not os.system('docker build -t csee/serverbase:latest ./serverbase/'):
    try:
      data = json.loads(get("/production/certificate_status/serverbase-build.cs.umbc.edu").text)
      if data['state'] == "signed":
        print "Cert already signed, deleting"
        delete("/production/certificate_status/serverbase-build.cs.umbc.edu")
      elif data['state'] == "requested":
        print "Cert has already been requested, deleting"
        delete("/production/certificate_status/serverbase-build.cs.umbc.edu")
      else:
        print "Unknown cert state:", data['state']
    except:
      print "Failed to get puppet cert information. Node may not exist yet."
    os.system('docker run -t -i '+RUN_FLAGS+' --name serverbase-build.cs.umbc.edu -h serverbase-build.cs.umbc.edu csee/serverbase:latest /usr/sbin/init')
    os.system('docker export serverbase-build.cs.umbc.edu | docker import - csee/serverbase:{date}'.format(date=date.today().isoformat()))
    os.system('docker tag csee/serverbase:{date} csee/serverbase:latest'.format(date=date.today().isoformat()))
    os.system('docker rm serverbase-build.cs.umbc.edu')


def randomMAC(hostname):
  random.seed(sum([ord(x) for x in hostname]))
  mac = [ 0x00, 0x16, 0x3e,
          random.randint(0x00, 0x7f),
          random.randint(0x00, 0xff),
          random.randint(0x00, 0xff) ]
  return ':'.join(map(lambda x: "%02x" % x, mac))

if args.action == 'mac':
  for i in args.containers:
    mac = randomMAC(i)
    print "The mac address for %s is %s" % (i, mac)

def runcontainer(i):
    volumes = " ".join(["-v "+x.strip() for x in config.get(i, 'volumes').split(',')])
    try:
      metadataraw = subprocess.check_output(['docker', 'inspect', '{i}.cs.umbc.edu'.format(i=i)])
    except subprocess.CalledProcessError:
      print i, "does not yet exist, creating..."
      try:
        data = json.loads(get("/production/certificate_status/{i}.cs.umbc.edu".format(i=i)).text)
        if data['state'] == "signed":
          print "Cert already signed, deleting"
          delete("/production/certificate_status/{i}.cs.umbc.edu".format(i=i))
        elif data['state'] == "requested":
          print "Cert has already been requested, deleting"
          delete("/production/certificate_status/{i}-build.cs.umbc.edu".format(i=i))
        else:
          print "Unknown cert state:", data['state']
      except:
        print "Failed to get puppet cert information. Node may not exist yet."
      os.system('docker run -d --net=none '+RUN_FLAGS+' -h {i}.cs.umbc.edu {volumes} \
        --name={i}.cs.umbc.edu csee/{i}:latest /usr/sbin/init'.format(i=i, volumes=volumes))
      metadataraw = subprocess.check_output(['docker', 'inspect', '{i}.cs.umbc.edu'.format(i=i)])
    metadata = json.loads(metadataraw)
    if not metadata[0]['State']['Running']:
      os.system('docker start {i}.cs.umbc.edu'.format(i=i))
    mac = randomMAC(i)
    print "Using mac:", mac
    try:
      metadataraw = subprocess.check_output(['docker', 'inspect', '{i}.cs.umbc.edu'.format(i=i)])
      metadata = json.loads(metadataraw)
      pid = metadata[0]['State']['Pid']
      print "Container is using pid:", pid
      if not os.path.isdir("/var/run/netns"):
        print "Creating /var/run/netns"
        os.mkdir("/var/run/netns")
      if not os.path.islink("/var/run/netns/%s" % str(pid)):
        os.symlink("/proc/%s/ns/net" % str(pid), "/var/run/netns/%s" % str(pid))
      os.system("ip link add veth-{i} type veth peer name host0-{i}".format(i=i))
      os.system("ip link set dev host0-{i} address {mac}".format(i=i, mac=mac))
      os.system("ip link set dev veth-{i} promisc on".format(i=i))
      os.system("ip link set dev veth-{i} up".format(i=i))
      os.system("ip link set dev veth-{i} master br0".format(i=i))
      os.system("ip link set host0-{i} netns {pid}".format(i=i, pid=pid))
      os.system("ip netns exec {pid} ip link set dev host0-{i} name host0".format(i=i, pid=pid))
      ip = config.get(i, 'ipaddr')
      os.system("ip netns exec {pid} ip addr add {ip}/26 dev host0".format(pid=pid, ip=ip))
      route = config.get(i, 'defaultroute')
      os.system("ip link set dev veth-{i} up".format(i=i))
      time.sleep(8)
      os.system("ip netns exec {pid} ip route add default via {route}".format(pid=pid, route=route))
    except subprocess.CalledProcessError:
      sys.exit("Error occurred starting container")

if args.action == 'run':
  for i in args.containers:
    runcontainer(i)

if args.action == 'stop':
  for i in args.containers:
    try:
      metadataraw = subprocess.check_output(['docker', 'inspect', '{i}.cs.umbc.edu'.format(i=i)])
    except subprocess.CalledProcessError:
      print "Cannot stop {i}, it does not exist.".format(i=i)
      continue
    metadata = json.loads(metadataraw)
    if metadata[0]['State']['Running']:
      os.system('docker stop {i}.cs.umbc.edu'.format(i=i))


if args.action == 'enter':
  for i in args.containers:
    try:
      metadataraw = subprocess.check_output(['docker', 'inspect', '{i}.cs.umbc.edu'.format(i=i)])
    except subprocess.CalledProcessError:
      print "Cannot enter {i}, it does not exist.".format(i=i)
      continue
    metadata = json.loads(metadataraw)
    if metadata[0]['State']['Running']:
      os.system('nsenter -m -u -i -n -p -t {j}'.format(j=metadata[0]['State']['Pid']))
    else:
      print "Cannot enter {i}, it is not running.".format(i=i)

if args.action == 'rm':
  for i in args.containers:
    try:
      metadataraw = subprocess.check_output(['docker', 'inspect', '{i}.cs.umbc.edu'.format(i=i)])
    except subprocess.CalledProcessError:
      print "Cannot rm {i}, it does not exist.".format(i=i)
      continue
    metadata = json.loads(metadataraw)
    if metadata[0]['State']['Running']:
      os.system('docker stop {i}.cs.umbc.edu'.format(i=i))
      os.system('docker rm {i}.cs.umbc.edu'.format(i=i))

if args.action == 'resume-all':
  for i in config.sections():
    if i != "main":
      start = config.get(i, 'startonboot')
      if start == "true":
        runcontainer(i)
