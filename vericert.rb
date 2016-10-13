#!/usr/bin/env ruby

require 'net/http'
require 'uri'

module OpenSSL
  module X509
    class Certificate
      def cn
        self.subject.to_a.select { |a| a[0] == "CN" }.first[1]
      end
    end
  end

  class BN
    def to_hexa
      self.to_i.to_s(16).scan(/..?/).join(":")
    end
  end
end

def usage
  puts "vericert <url>"
end

if ARGV.size < 1
  usage
  exit
end

certs = []

uri = URI.parse(ARGV[0])
https = Net::HTTP.new(uri.host, uri.port)
https.use_ssl = true
https.verify_callback = proc { |ok, ctx|
  certs << ctx.current_cert
  true
}
https.head('/')

certs.each_with_index { |cert, i|
  case i
  when 0
    puts "Root CA"
  when certs.size-1
    puts "Server"
  else
    puts "Intermediate CA ##{i}"
  end

  puts "  CN: #{cert.cn}"
  puts "  Serial: #{cert.serial.to_hexa}"

  next if i == 0

  crl_uri = nil
  cert.extensions.each { |ext|
    if ext.oid == "crlDistributionPoints"
      if ext.value =~ /URI:(\S+)/
        crl_uri = $1
      else
        raise 'no URI in crlDistributionPoints: #{ext.value}'
      end
    end
  }

  puts "  CRL: #{crl_uri}"
  crl_in_der = Net::HTTP.get(URI.parse(crl_uri))
  crl = OpenSSL::X509::CRL.new(crl_in_der)

  crl.verify(certs[i-1].public_key)
  puts "    Verify: OK"

  if crl.revoked.any? { |r| r.serial == cert.serial }
    revoked = "YES!!!"
  else
    revoked = "no"
  end
  puts "    Revoked: #{revoked}"
}
