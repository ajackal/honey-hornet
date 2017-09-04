#!/usr/bin/expect

set user [lindex $argv 0]
set password [lindex $argv 1]
set f [open "targets.txt"]
set hosts [split [read $f] "\n"]
close $f

foreach host $hosts {
  spawn telnet "$host"
  expect "Login: "
  send "$user\n"
  expect "*?assword:*"
  send -- "$password\r"
  expect eof
  sleep 3
  send -- "quit\n"
  puts "True\n"
}
