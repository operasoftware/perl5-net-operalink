#
# High-level API interface to Opera Link
#
# http://www.opera.com/docs/apis/linkrest/
#

package Net::OperaLink;

our $VERSION = '0.03';

use feature qw(state);
use strict;
use warnings;

use Carp           ();
use CGI            ();
use Data::Dumper   ();
use LWP::UserAgent ();
use Net::OAuth 0.25;
use URI            ();
use JSON::XS       ();

use Net::OperaLink::Bookmark;
use Net::OperaLink::Note;
use Net::OperaLink::Speeddial;

# Opera supports only OAuth 1.0a
$Net::OAuth::PROTOCOL_VERSION = &Net::OAuth::PROTOCOL_VERSION_1_0A;

use constant {
    LINK_SERVER    => 'https://link.api.opera.com',
    OAUTH_PROVIDER => 'auth.opera.com',
};

# API/OAuth URLs
use constant {
    LINK_API_URL   => LINK_SERVER . '/rest',
    OAUTH_BASE_URL => 'https://' . OAUTH_PROVIDER . '/service/oauth',
};

sub new {
    my ($class, %opts) = @_;

    $class = ref $class || $class;

    for (qw(consumer_key consumer_secret)) {
        if (! exists $opts{$_} || ! $opts{$_}) {
            Carp::croak "Missing '$_'. Can't instance $class\n";
        }
    }

    my $self = {
        _consumer_key => $opts{consumer_key},
        _consumer_secret => $opts{consumer_secret},
        _access_token => undef,
        _access_token_secret => undef,
        _request_token => undef,
        _request_token_secret => undef,
        _authorized => 0,
    };

    bless $self, $class;

    return $self;
}

sub authorized {
    my ($self) = @_;

    # We assume to be authorized if we have access token and access token secret
    my $acc_tok = $self->access_token();
    my $acc_tok_secret = $self->access_token_secret();

    # TODO: No real check if the token is still valid
    unless ($acc_tok && $acc_tok_secret) {
        return;
    }

    return 1;
}

sub access_token {
    my $self = shift;
    if (@_) {
        $self->{_access_token} = shift;
    }
    return $self->{_access_token};
}

sub access_token_secret {
    my $self = shift;
    if (@_) {
        $self->{_access_token_secret} = shift;
    }
    return $self->{_access_token_secret};
}

sub consumer_key {
    my ($self) = @_;
    return $self->{_consumer_key};
}

sub consumer_secret {
    my ($self) = @_;
    return $self->{_consumer_secret};
}

sub request_token {
    my $self = shift;
    if (@_) {
        $self->{_request_token} = shift;
    }
    return $self->{_request_token};
}

sub request_token_secret {
    my $self = shift;
    if (@_) {
        $self->{_request_token_secret} = shift;
    }
    return $self->{_request_token_secret};
}

sub get_authorization_url {
    my ($self) = @_;

    # TODO: Get a request token first
    # and then build the authorize URL
    my $oauth_resp = $self->request_request_token();

    warn 'CONTENT=' . $oauth_resp;

    my $req_tok = $oauth_resp->{oauth_token};
    my $req_tok_secret = $oauth_resp->{oauth_token_secret};

    if (! $req_tok || ! $req_tok_secret) {
        Carp::croak("Couldn't get a valid request token from " . OAUTH_BASE_URL);
    }

    # Store in the object for the access-token phase later
    $self->request_token($req_tok);
    $self->request_token_secret($req_tok_secret);

    return $self->oauth_url_for('authorize', oauth_token=> $req_tok);
}

sub _do_oauth_request {
    my ($self, $url) = @_;

    my $ua = $self->_user_agent();
    my $resp = $ua->get($url);

	if ($resp->is_success) {
		my $query = CGI->new($resp->content());
		return {
			ok => 1,
            response => $resp,
            content => $resp->content(),
            data => { $query->Vars },
		};
	}

	return {
		ok => 0,
        response => $resp,
        content => $resp->content(),
		errstr => $resp->status_line(),
	}

}

sub _user_agent {
    my $ua = LWP::UserAgent->new();
    return $ua;
}

sub oauth_url_for {
    my ($self, $step, %args) = @_;

    $step = lc $step;

    my $url = URI->new(OAUTH_BASE_URL . '/' . $step);
    $url->query_form(%args);

    return $url;
}

sub request_access_token {
    my ($self, %args) = @_; 

    if (! exists $args{verifier}) { 
        Carp::croak "The 'verifier' argument is required. Check the docs."; 
    } 

    my $verifier = $args{verifier};

    my %opt = (
        step           => 'access_token',
        request_method => 'GET',
        request_url    => $self->oauth_url_for('access_token'),
        token          => $self->request_token(),
        token_secret   => $self->request_token_secret(),
        verifier       => $verifier,
    );

    my $request = $self->_prepare_request(%opt);
    if (! $request) {
        Carp::croak "Unable to initialize access-token request";
    }

    my $access_token_url = $request->to_url();

    #print 'access_token_url:', $access_token_url, "\n";

    my $response = $self->_do_oauth_request($access_token_url);

    # Check if the request-token request failed
    if (! $response || ref $response ne 'HASH' || $response->{ok} == 0) {
        Carp::croak "Access-token request failed. Might be a temporary problem. Please retry later.";
    }

    $response = $response->{data};

    # Store access token for future requests
    $self->access_token($response->{oauth_token});
    $self->access_token_secret($response->{oauth_token_secret});
 
    # And return them as well, so user can save them to persistent storage
    return (
        $response->{oauth_token},
        $response->{oauth_token_secret}
    );
}

sub request_request_token {
    my ($self) = @_;

    my %opt = (
        step => 'request_token',
        callback => 'oob',
        request_method => 'GET',
        request_url => $self->oauth_url_for('request_token'),
    );

    my $request = $self->_prepare_request(%opt);
    if (! $request) {
        Carp::croak "Unable to initialize request-token request";
    }

    my $request_token_url = $request->to_url();

    my $response = $self->_do_oauth_request($request_token_url);

    # Check if the request-token request failed
    if (! $response || ref $response ne 'HASH' || $response->{ok} == 0) {
        Carp::croak "Request-token request failed. Might be a temporary problem. Please retry later.";
    }

    return $response->{data};
}

sub _fill_default_values {
    my ($self, $req) = @_;

    $req ||= {};

    $req->{step}  ||= 'request_token';
    $req->{nonce} ||= _random_string(32);
    $req->{request_method} ||= 'GET';
    $req->{consumer_key} ||= $self->consumer_key();
    $req->{consumer_secret} ||= $self->consumer_secret();
    # Opera OAuth provider supports only HMAC-SHA1
    $req->{signature_method} = 'HMAC-SHA1';
    $req->{timestamp} ||= time();
    $req->{version} = '1.0';

    return $req;
}

sub _prepare_request {
    my ($self, %opt) = @_;

    # Fill in the default OAuth request values
    $self->_fill_default_values(\%opt);

    # Use Net::OAuth to obtain a valid request object
    my $step = delete $opt{step};
    my $request = Net::OAuth->request($step)->new(%opt);

    # User authorization step doesn't need signing
    if ($step ne 'user_auth') {
        $request->sign;
    }

    return $request;
}

sub _random_string {
    my ($length) = @_;
    if (! $length) { $length = 16 } 
    my @chars = ('a'..'z','A'..'Z','0'..'9');
    my $str = '';
    for (1 .. $length) {
        $str .= $chars[ int rand @chars ];
    }
    return $str;
}

sub api_get_request {
    my ($self, $datatype, @args) = @_;

    my $api_url = $self->api_url_for($datatype, @args);

    $api_url->query_form(
        oauth_token => $self->access_token(),
        api_output => 'json',
    );

    #warn "api-url: $api_url\n";
    #print 'acc-tok:', $self->access_token(), "\n";
    #print 'acc-tok-sec:', $self->access_token_secret(), "\n";

    my %opt = (
        step           => 'protected_resource',
        request_method => 'GET',
        request_url    => $api_url,
        token          => $self->access_token(),
        token_secret   => $self->access_token_secret(),
    );

    my $request = $self->_prepare_request(%opt);
    if (! $request) {
        Carp::croak('Unable to initialize api request');
    }

    my $oauth_url = $request->to_url();
    my $response = $self->_do_oauth_request($oauth_url);

    #warn "api-url: $oauth_url\n";
    #warn "response: " . Data::Dumper::Dumper($response) . "\n";

    if (! $response || ref $response ne 'HASH' || $response->{ok} == 0) {
        $self->error($response->{status});
        return;
    }

    # Given a HTTP::Response, return the data hash
    return $self->api_result($response->{response});
}

sub error {
    my $self = shift;

    if (@_) {
        $self->{error} = shift;
    }

    return $self->{error};
}

sub _json_decoder {
    state $json_obj = JSON::XS->new();
    return $json_obj;
}

sub api_result { 
    my ($self, $res) = @_;
    my $json_str = $res->content;
    my $json_obj = $self->_json_decoder();
    return $json_obj->decode($json_str);
}

sub api_url_for {
    my ($self, @args) = @_;

    my $datatype = shift @args;
    my $root_url = LINK_API_URL;
    my $uri;

    $datatype = ucfirst lc $datatype;

    # Net::OperaLink + '::' + Bookmark/Speeddial/...
    my $package = join('::', ref($self), $datatype);

    #warn "package=$package\n";
    #warn "args=".join(',',@args)."\n";
    #warn "api_url_for=" . $package->api_url_for(@args) . "\n";

    eval {
        $uri = URI->new(
            $root_url . "/" . $package->api_url_for(@args) . "/"
        )
    } or do {
        Carp::croak("Unknown or unsupported datatype $datatype ?");
    };

    return $uri;
}

sub _datatype_query_node {
    my ($self, $datatype, $id, $query_mode) = @_;

    if (not defined $id or not $id) {
        $self->error("Incorrect API usage: $datatype(\$id) or $datatype(\$id, \$query_mode)");
        return;
    }

    return $self->api_get_request($datatype, $id);
}

sub _datatype_query_subtree {
    my ($self, $datatype, $query_mode) = @_;

    $query_mode ||= 'children';

    return $self->api_get_request($datatype, $query_mode);
}

sub bookmark {
    my ($self, $id, $query_mode) = @_;
    return $self->_datatype_query_node('bookmark', $id, $query_mode);
}

sub bookmarks {
    my ($self, $query_mode) = @_;
    return $self->_datatype_query_subtree('bookmark', $query_mode);
}

sub note {
    my ($self, $id, $query_mode) = @_;
    return $self->_datatype_query_node('note', $id, $query_mode);
}

sub notes {
    my ($self, $query_mode) = @_;
    return $self->_datatype_query_subtree('note', $query_mode);
}

sub speeddial {
    my ($self, $id, $query_mode) = @_;
    return $self->_datatype_query_node('speeddial', $id, $query_mode);
}

sub speeddials {
    my ($self, $query_mode) = @_;
    return $self->_datatype_query_subtree('speeddial', $query_mode);
}

1;

