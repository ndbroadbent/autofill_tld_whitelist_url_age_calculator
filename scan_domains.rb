#!/usr/bin/env ruby

require 'bundler/setup'
require 'httparty'
require 'whois'
require 'whois-parser'
require 'pry-byebug'

TLD_URL = 'https://cdn.smoot.apple.com/static/autofill_tld_whitelist_url'
TLD_PATH = File.join(__dir__, 'tlds.json')
SCANNED_PATH = File.join(__dir__, 'scanned.json')

# Broken WHOIS records / parsing
BLOCK_LIST = [ 'giants.it' ]

unless File.exist?(TLD_PATH)
  puts "Fetching tld list from #{TLD_URL}..."
  response = HTTParty.get(TLD_URL)
  File.write(TLD_PATH, response.body)
end

latest_created_on = nil
latest_tld = nil
scanned = []
if File.exist?(SCANNED_PATH)
  scan_contents = JSON.parse(File.read(SCANNED_PATH))
  scanned = scan_contents['scanned']
  latest_created_on = Time.parse(scan_contents['latest_created_on']['date'])
  latest_tld = scan_contents['latest_created_on']['tld']
end

tlds = (JSON.parse(File.read(TLD_PATH))['tlds'] - scanned).uniq

at_exit do
  puts "Writing scanned domains to #{SCANNED_PATH}..."
  File.write(SCANNED_PATH, JSON.pretty_generate({
    scanned: scanned,
    latest_created_on: { date: latest_created_on, tld: latest_tld }
  }))
end

while tlds.any?
  next_tld = tlds.sample
  scanned << next_tld
  next if BLOCK_LIST.include?(next_tld)

  printf "Looking up: #{next_tld}    "

  begin
    record = Whois.whois(next_tld)
    parser = record.parser
    unless parser.created_on
      puts "Could not parse created_on"
      next
    end

  rescue StandardError => e
    puts "Error: #{e}"
    next
  end
  
  puts "Created at: #{parser.created_on.strftime('%Y-%m-%d %H:%M:%S')}"

  if latest_created_on.nil? || latest_created_on < parser.created_on
    latest_created_on = parser.created_on
    latest_tld = next_tld
  end

  puts "================== Youngest domain so far: #{latest_tld} created at: #{latest_created_on.strftime('%Y-%m-%d %H:%M:%S')}"
end
