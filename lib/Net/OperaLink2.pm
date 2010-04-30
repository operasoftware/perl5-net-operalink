package Net::OperaLink;

our $VERSION = '0.01';

use strict;
use warnings;

use Carp           ();
use Data::Random   ();
use Data::Dumper   ();
use HTTP::Request::Common;
use LWP::UserAgent ();
use Net::OAuth     ();

use constant OAUTH_SERVER => 'https://auth-test.opera.com';
use constant LINK_SERVER  => 'http://link-test.opera.com:8000';

sub useragent {
    my $ua = LWP::UserAgent->new();
    $ua->agent("Net::OperaLink/$VERSION");
    return $ua;
}

sub new {
    my ($class, $opt) = @_;

    $class = ref $class || $class;
    $opt ||= {};

    if (not exists $opt->{consumer_key}) {
        Carp::croak("Need 'consumer_key' to proceed");
    }
    
    if (not exists $opt->{consumer_secret}) {
        Carp::croak("Need 'consumer_secret' to proceed");
    }

    my $self = {
        consumer_key => $opt->{consumer_key},
        consumer_secret => $opt->{consumer_secret},
    };

    bless $self, $class;
    return $self;
}

sub consumer_key {
    $_[0]->{consumer_key};
}

sub consumer_secret {
    $_[0]->{consumer_secret};
}

sub error {
    my ($self) = @_;

    if (@_) {
        $self->{error} = shift;
    }

    return $self->{error};
}

sub request_token {
    my ($self) = @_;

    my $request = Net::OAuth->request("request token")->new(
        consumer_key => $self->consumer_key(),
        consumer_secret => $self->consumer_secret(),
        request_url => "http://auth-test.opera.com/service/oauth/request_token",
        request_method => 'POST',
        signature_method => 'HMAC-SHA1',
        timestamp => time,
        nonce => join('', Data::Random::rand_chars(size=>16, set=>'alphanumeric')),
        version => "1.0",
        callback => "oop",
    );

    $request->sign;

    unless ($request->verify) {
        Carp::croak("Couldn't get a request token. Check OAuth parameters.\n");
    }

    my $ua = $self->useragent();
    my $res = $ua->request(POST($request->to_url));

    if ($res->is_success) {
        my $response = Net::OAuth->response('request token')->from_post_body($res->content);
        return {
            token => $response->token(),
            token_secret => $response->token_secret(),
        };
    }

    $self->error($res);
    return;

}

1;

