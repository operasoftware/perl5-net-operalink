#!/usr/bin/env perl
#
# Consumer sends Request Token Request
#
# $Id: request_token.pl 15810 2009-11-24 12:38:27Z cosimo $

use Net::OAuth     ();
use HTTP::Request::Common;
use LWP::UserAgent ();
use Data::Random   ();
use Data::Dumper   ();

my $ua = LWP::UserAgent->new();

my $request = Net::OAuth->request("request token")->new(
    consumer_key => 'demo_key',
    consumer_secret => 'demo_secret',
    request_url => "http://auth-test.opera.com/service/oauth/request_token",
    request_method => 'POST',
    signature_method => 'HMAC-SHA1',
    timestamp => time,
    nonce => join('', Data::Random::rand_chars(size=>16, set=>'alphanumeric')),
    version => "1.0",
    callback => "oop",
);

$request->sign;

die "COULDN'T VERIFY! Check OAuth parameters.\n" unless $request->verify;

my $res = $ua->request(POST $request->to_url); # Post message to the Service Provider

if ($res->is_success) {
    my $response = Net::OAuth->response('request token')->from_post_body($res->content);
    print "Got Request Token ", $response->token, "\n";
    print "Got Request Token Secret ", $response->token_secret, "\n";
}
else {
    print Data::Dumper::Dumper($res);
}

