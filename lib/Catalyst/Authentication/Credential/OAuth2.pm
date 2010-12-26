package Catalyst::Authentication::Credential::OAuth2;

use Moose;
use MooseX::Types::Moose qw(ArrayRef);
use MooseX::Types::Common::String qw(NonEmptySimpleStr);
use Net::OAuth2::Client;
use namespace::autoclean;


has [qw(application_id application_secret site)] => (
    is       => 'ro',
    isa      => NonEmptySimpleStr,
    required => 1,
);

has [qw(authorize_path authorize_url access_token_path access_token_url)] => (
    is       => 'ro',
    isa      => NonEmptySimpleStr,
    required => 0,
);

has oauth_args => (
    is      => 'ro',
    isa     => ArrayRef,
    default => sub { [] },
);

has _oauth => (
    is      => 'ro',
    isa     => 'Net::OAuth2::Client',
    lazy    => 1,
    builder => '_build__oauth',
);

sub _build__oauth {
    my ($self) = @_;

    return Net::OAuth2::Client->new(
        (map { ($self->$_) } qw(application_id application_secret)),
        (map { ($_ => $self->$_) } qw(site authorize_path authorize_url access_token_path access_token_url)),
        @{ $self->oauth_args },
        access_token_method => 'POST',
    );
}

sub BUILDARGS {
    my ($self, $config, $ctx, $realm) = @_;

    return $config;
}

sub BUILD {
    my ($self) = @_;

    $self->_oauth;
}


sub authenticate {
    my ($self, $ctx, $realm, $auth_info) = @_;

    if ( defined( my $code = $ctx->request->params->{code} ) ) {
        my $token = $self->_oauth
            ->web_server( redirect_uri =>  $ctx->request->base . $ctx->request->path )
            ->get_access_token( $code, grant_type => 'authorization_code' );

        die 'Error validating verification code' unless $token;

        return $realm->find_user( {
            token => $token->{access_token},
        }, $ctx );
    }
    else {
        my $url = $self->_oauth
            ->web_server( redirect_uri =>  $ctx->request->uri )
            ->authorize_url( %{ $auth_info } );
        $ctx->response->redirect( $url );
        return;
    }
}

__PACKAGE__->meta->make_immutable;


1;

__END__
