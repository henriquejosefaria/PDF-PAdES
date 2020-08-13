package signpdf_cli;
#Linha de comando para assinar um documento PDF através do DSS e CMD.



use Crypt::OpenSSL::X509;
use DateTime;
use Digest::SHA qw(sha256);
use MIME::Base64;
use Getopt::Long;
use POSIX qw(strftime);
use List::MoreUtils ':like_0.33';
use warnings;
use IO::Prompt;
use Carp;
use FindBin;               # locate this script
use lib "$FindBin::Bin/";  # use this directory

use signpdf_config;
use dss_rest_msg;
use cmd_soap_msg;
use verifiers;

use strict;

my $VERSION = "version: 1.0";
my $dss_rest = signpdf_config::get_rest();
my $APPLICATION_ID = signpdf_config::get_appid();

#Função main do programa.

#Verifica se o APPLICATION_ID está definido
die "Configure o APPLICATION_ID\n" unless defined $APPLICATION_ID;

#Verificação de um número de inputs suficiente
my $number_of_args = $#ARGV + 1;
#if($number_of_args == 0){
#    die "usage: signpdf_cli.pl [-h]\n\n";
#}

#Faz o parser dos argumentos recebidos
my  @arguments = &args_parse;
if (!defined($arguments[5])){
    $arguments[5] = $arguments[3];
}

my $wsdl_to_use = cmd_soap_msg::get_wsdl(1);

cmd_soap_msg::debug($arguments[8]);
dss_rest_msg::debug($arguments[8]);

$arguments[9] = $APPLICATION_ID;

signpdf($wsdl_to_use,\@arguments);



sub args_parse{
    # VERIFICAR TAMANHO DO INPUT, O PERL PERMITE CRESCIMENTO ATÉ AO FIM DA STACK DA RAM
    my @parsed_arguments;
    $parsed_arguments[0] = 'run';
    GetOptions(
        'h'          => \(my $help),
        'v'          => \(my $version),
        'u=s'        => \$parsed_arguments[1],
        'p=s'        => \$parsed_arguments[2],
        'infile=s'   => \$parsed_arguments[3],
        'outfile:s'  => \$parsed_arguments[5],
        'datetime:s' => \$parsed_arguments[6],
        'prod'       => \($parsed_arguments[7] = 1), #default value is 1 (for this program is always 1)
        'd'          => \($parsed_arguments[8] = 0), #default value is 0 -> sem debug
    );
    if(defined($version)){
        die "$VERSION\n";
    }

    if(defined($help)){
        print "usage: signpdf_cli.py [-h] [-V] -u USER -p PIN -infile INFILE [-outfile OUTFILE] [-datetime DATETIME] [-D]\n\nPDF PAdES (DSS & CMD) signature Command Line Program, by DeviseFutures, Lda.\n\n";  
        info(['-u','-p','-infile']); 
    }
    else{
        verifier(\@parsed_arguments);
    }
    return @parsed_arguments;
}

sub info{
    my @info = @_;
    my %help = (
        '-h'        => 'show this help message and exit',
        '-u'        => 'user phone number ( -u +XXX NNNNNNNNN)',
        '-p'        => 'CMD signature PIN',
        '-infile'   => 'PDF file to sign',
        '-v'        => 'show program version',
        '-outfile'  => 'Signed PDF file (default: <infile>.signed.pdf)',
        '-datetime' => '\"DD-MM-YYYYThh:mm:ss.ssssss\" format (default: current time and date)',
        '-d'        => 'show debug information'
        );
    print "\nPositional Arguments:\n";
    map { print "$_    => $help{$_}\n"; } @info ;
    print "\nOptional Arguments:\n";
    my @Array = ('-h','-v','-outfile','-datetime','-d');
    map { print "$_  " . " " x (9-length($_)) . "  => $help{$_}\n"; } @Array ;
    exit 1;
}

sub verifier{
    my @aux_array = @_;
    my @args = @{$aux_array[0]};
    #Verifica que dados mandatórios são fornecidos 
    die "Missing values. Insert the madatory data!\n" unless (defined($args[1]) and defined($args[2]) and defined($args[3]));

    verifiers::input(\@args);
    map{die "I know what your up to! Don't try to SQL inject me!!\n" unless verifiers::sqlInjection($_) == 0;} @args;
    map{die "I know what your up to! Don't try to XML inject me!!\n" unless verifiers::xmlInjection($_) == 0;} @args;
    return 1;
}


sub signpdf{
=head
    Assina o PDF em formato PAdES, recorrendo ao DSS e CMD.

    Parameters
    ----------
    args : dictionary
        Parâmetros passado pelo comando linha.

    Returns
    -------
    int
        Devolve 0 na conclusão com sucesso da função.
=cut
    my @auxiliar = @_;
    my $client = $auxiliar[0];
    my @args = @{$auxiliar[1]};
    #certs[0] = user; certs[1] = root; certs[2] = CA
    my @cmd_certs = cmd_soap_msg::getcertificate($client, \@args);
    map {croak 'Ups! Something went wrong with the certificates! They haven\'t been returned!\n' unless defined($_);} @cmd_certs;
    
    map {Crypt::OpenSSL::X509->new_from_string($_, Crypt::OpenSSL::X509::FORMAT_PEM)} @cmd_certs;

    # Lê ficheiro PDF
    my $content;
    open(my $fh, "<", $args[3]) or die "Ficheiro " . $args[3] . " não encontrado.\n"; # previne pipelining
    {
        local $/ = undef;
        $content = <$fh>;
    }
    close($fh);
    my %pdf = ('bytes' => $content, 'name' => $args[3],);

    my $signdate;
    # Identifica hora/data de assinatura
    if (!defined($args[6])){
        $signdate = DateTime->now()->strftime( '%Y-%m-%dT%H:%M:%S.%6N');
    }
    else{
        $signdate = $args[6];
    }

    my @certs = apply{ $_ =~ s/\s*-----\s*BEGIN CERTIFICATE\s*-----\s*//;} @cmd_certs;
    @certs = apply{ $_ =~ s/\s*-----\s*END CERTIFICATE\s*-----\s*//;} @certs;

    # Obtém o DTBS do PDF e gera a hash a assinar
    my $response = dss_rest_msg::getDataToSign(\@certs, $signdate, \%pdf, $dss_rest);
    die "Server side fail! Data to sign was not returned!\n" unless defined($response);
    verifiers::valid_response($response);
    $args[10] = sha256(decode_base64($response));

    # Obtém assinatura da hash
    my $process_id = cmd_soap_msg::ccmovelsign($client, \@args, "SHA256");
    die "Server side fail! ProcessId was not returned!\n" unless defined($process_id);
    verifiers::valid_processId($process_id);
    $args[11] = $process_id;

    my $otp = prompt "Introduza o OTP recebido no seu dispositivo:";
    # Removes new line from the input 
    chomp $otp;
    verifiers::valid_otp($otp); 
    $args[4] = $otp;

    my $signature = cmd_soap_msg::validate_otp($client, \@args);
    die "Server side fail! Signature was not returned!\n" unless defined($signature);
    verifiers::valid_Signature($signature);

    # Assina PDF
    $response = dss_rest_msg::signDocument(\@certs, $signdate, \%pdf, $signature, $dss_rest);
    die "Server side fail! Signed Document was not returned!\n" unless defined($response);

    # Grava PDF
    open(my $fd, '>', $args[5]) or die "Impossível abrir ficheiro!!\n";
    {
        local $/ = undef;
        print $fd decode_base64($response);
    }
    close($fd);
    print("Ficheiro assinado guardado em " . $args[5] . "\n\n");
    return 1;
}


1;

